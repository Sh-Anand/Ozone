//
// Created by Zikai Liu on 5/3/22.
//

#include <aos/aos_rpc.h>
#include <aos/nameserver.h>
#include <sys/queue.h>
#include <spawn/spawn.h>
#include <aos/rpc_handler_builder.h>
#include <sys/tree.h>

#define MAX_ENUM_COUNT 256

struct program {
    domainid_t pid;
    struct aos_chan chan;
    struct aos_chan notifier;  // send only
    LIST_ENTRY(program) link;
};

static LIST_HEAD(, program) programs = LIST_HEAD_INITIALIZER(&programs);

struct service {
    char *name;  // hold the life cycle
    struct program *program;
    RB_ENTRY(service) rb_entry;
};

static int service_cmp(struct service *n1, struct service *n2)
{
    return strcmp(n1->name, n2->name);
}

static RB_HEAD(service_rb_tree, service) services;

RB_PROTOTYPE(service_rb_tree, service, rb_entry, service_cmp)
RB_GENERATE(service_rb_tree, service, rb_entry, service_cmp)

static struct service *find_service(char *name)
{
    struct service find;
    find.name = name;
    return RB_FIND(service_rb_tree, &services, &find);
}

static AOS_CHAN_HANDLER(nameserver_urpc_handler);

RPC_HANDLER(nameserver_bind)
{
    CAST_IN_MSG_EXACT_SIZE(msg, domainid_t);
    domainid_t pid = *msg;
    struct capref frame = in_cap;

//    DEBUG_PRINTF("process %u bind\n", pid);

    errval_t err;

    struct program *b = malloc(sizeof(*b));
    if (b == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    memset(b, 0, sizeof(*b));

    b->pid = pid;

    // The input frame contains two UMP channels
    struct frame_identity frame_id;
    err = frame_identify(frame, &frame_id);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_IDENTIFY);
    }
    if (frame_id.bytes != UMP_CHAN_SHARED_FRAME_SIZE * 2) {
        return err_push(err, LIB_ERR_UMP_INVALID_FRAME_SIZE);
    }

    uint8_t *buf = NULL;
    err = paging_map_frame(get_current_paging_state(), (void **)&buf,
                           UMP_CHAN_SHARED_FRAME_SIZE * 2, frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP);
    }

    // First half for RPC
    err = aos_chan_ump_init_from_buf(&b->chan, buf, UMP_CHAN_SERVER, pid);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE;
    }
    err = aos_chan_register_recv(&b->chan, get_default_waitset(), nameserver_urpc_handler,
                                 b);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE;
    }

    // Second half for listener
    err = aos_chan_ump_init_from_buf(&b->notifier, buf + UMP_CHAN_SHARED_FRAME_SIZE,
                                     UMP_CHAN_CLIENT, pid);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE;
    }

    LIST_INSERT_HEAD(&programs, b, link);
    return SYS_ERR_OK;

FAILURE:
    aos_chan_destroy(&b->chan);
    aos_chan_destroy(&b->notifier);
    if (buf) {
        paging_unmap(get_current_paging_state(), buf);
    }
    free(b);
    return err;
}

RPC_HANDLER(nameserver_kill_by_pid)
{
    CAST_IN_MSG_EXACT_SIZE(msg, domainid_t);
    domainid_t pid = *msg;

    struct service *s, *tmp;
    RB_FOREACH_SAFE(s, service_rb_tree, &services, tmp) {
        if (s->program->pid == pid) {
            RB_REMOVE(service_rb_tree, &services, s);
            free(s);
        }
    }

    // FIXME: delete programs and notifier the remaining programs

    return SYS_ERR_OK;
}

static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT];

/**
 * Nameserver URPC handler
 * @param arg  *struct client
 */
static AOS_CHAN_HANDLER(nameserver_urpc_handler)
{
    if (identifier >= NAMESERVICE_RPC_COUNT || rpc_handlers[identifier] == NULL) {
        DEBUG_PRINTF("%s: invalid URPC msg %u\n", __func__, NAMESERVICE_RPC_COUNT);
        return ERR_INVALID_ARGS;
    }
    return rpc_handlers[identifier](arg, in_payload, in_size, out_payload, out_size,
                                    in_cap, out_cap);
}

RPC_HANDLER(handle_register)
{
    struct program *server = arg;

    CAST_IN_MSG_AT_LEAST_SIZE(name, char);

//    DEBUG_PRINTF("process %u register \"%s\"\n", server->pid, name);

    // Check for duplication
    if (find_service(name) != NULL) {
        return NAMESERVER_ERR_NAME_CONFLICT;
    }

    // Register the service
    struct service *service = malloc(sizeof(*service));
    if (service == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    service->name = strdup(name);
    service->program = server;
    RB_INSERT(service_rb_tree, &services, service);

    return SYS_ERR_OK;
}

RPC_HANDLER(handle_deregister)
{
    struct program *server = arg;

    CAST_IN_MSG_AT_LEAST_SIZE(name, char);

//    DEBUG_PRINTF("%u process deregister \"%s\"\n", server->pid, name);

    struct service *service = find_service(name);
    if (service == NULL) {
        return NAMESERVER_ERR_NOT_FOUND;
    }
    if (service->program != server) {
        return NAMESERVER_ERR_DEREG_NOT_ALLOWED;
    }
    RB_REMOVE(service_rb_tree, &services, service);
    free(service->name);
    free(service);
    return SYS_ERR_OK;
}

RPC_HANDLER(handle_lookup)
{
    struct program *client = arg;
    errval_t err;

    CAST_IN_MSG_AT_LEAST_SIZE(name, char);

//    DEBUG_PRINTF("process %u lookup \"%s\"\n", client->pid, name);

    struct service *service = find_service(name);
    if (service == NULL) {
        return NAMESERVER_ERR_NOT_FOUND;
    }

    struct capref frame;
    err = frame_alloc(&frame, UMP_CHAN_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // DEBUG_PRINTF("> process %u lookup \"%s\"\n", client->pid, name);

    struct program *server = service->program;
    MALLOC_WITH_SIZE(server_reply, struct ns_binding_notification,
                     sizeof(domainid_t) + strlen(name) + 1);
    server_reply->pid = client->pid;
    memcpy(server_reply->name, name, strlen(name) + 1);
    err = aos_chan_send(&server->notifier, SERVER_BIND_UMP, frame, server_reply,
                        sizeof(domainid_t) + strlen(name) + 1, false);
    if (err_is_fail(err)) {
        return err;
    }

    MALLOC_OUT_MSG(reply, domainid_t);
    *reply = server->pid;
    *out_cap = frame;
    return SYS_ERR_OK;

    // DEBUG_PRINTF(">> process %u lookup \"%s\"\n", client->pid, name);
}

// https://stackoverflow.com/a/4771038/10087792
static bool startswith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : memcmp(pre, str, lenpre) == 0;
}

RPC_HANDLER(handle_enumerate)
{
//    struct program *client = arg;
//    errval_t err;

    CAST_IN_MSG_AT_LEAST_SIZE(query, char);

//    DEBUG_PRINTF("process %u enumerate \"%s\"\n", client->pid, query);

    struct service *matched[MAX_ENUM_COUNT];
    size_t count = 0;
    size_t buf_size = 0;

    struct service *s;
    RB_FOREACH(s, service_rb_tree, &services) {
        if (startswith(query, s->name)) {
            matched[count++] = s;
            buf_size += strlen(s->name) + 1;
        }
    }

    MALLOC_OUT_MSG_WITH_SIZE(reply, struct ns_enumerate_reply_msg, sizeof(struct ns_enumerate_reply_msg) + buf_size);
    reply->num = count;
    char *buf = reply->buf;
    for (int i = 0; i < count; ++i) {
        size_t len = strlen(matched[i]->name);
        memcpy(buf, matched[i]->name, len + 1);
        buf += len + 1;
    }

    return SYS_ERR_OK;

    // DEBUG_PRINTF(">> process %u lookup \"%s\"\n", client->pid, name);
}

// Empty entries are NULL since it's a global variable
static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT] = {
    [NAMESERVICE_REGISTER] = handle_register,
    [NAMESERVICE_DEREGISTER] = handle_deregister,
    [NAMESERVICE_LOOKUP] = handle_lookup,
    [NAMESERVICE_ENUMERATE] = handle_enumerate,
};

struct aos_chan init_listener;

static AOS_CHAN_HANDLER(init_msg_handler)
{
    switch (identifier) {
    // XXX: magic numbers, put them in a shared header
    case 0:
        return nameserver_bind(NULL, in_payload, in_size, out_payload, out_size, in_cap,
                               out_cap);
    case 1:
        return nameserver_kill_by_pid(NULL, in_payload, in_size, out_payload, out_size, in_cap,
                               out_cap);
    default:
        return ERR_INVALID_ARGS;
    }

}

int main(int argc, char *argv[])
{
    errval_t err;

    struct capref init_listener_ep = { .cnode = cnode_task, .slot = TASKCN_SLOTS_FREE };

    if (capref_is_null(init_listener_ep)) {
        DEBUG_PRINTF("init does not provide listener ep\n");
        exit(EXIT_FAILURE);
    }

    // The following call include sending the local cap to complete setup
    err = aos_chan_lmp_accept(&init_listener, 32, init_listener_ep);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init init_listener\n");
        exit(EXIT_FAILURE);
    }

    // The following call includes lmp_chan_alloc_recv_slot
    err = aos_chan_register_recv(&init_listener, get_default_waitset(), init_msg_handler,
                                 NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to listen on init_listener\n");
        exit(EXIT_FAILURE);
    }

    DEBUG_PRINTF("nameserver starts\n");

    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}