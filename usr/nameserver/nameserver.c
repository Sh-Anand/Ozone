//
// Created by Zikai Liu on 5/3/22.
//

#include "aos/aos_rpc.h"
#include "aos/nameserver.h"
#include "sys/queue.h"
#include "spawn/spawn.h"
#include "aos/lmp_handler_builder.h"
#include "aos/ump_handler_builder.h"
#include "aos/rpc_handler_builder.h"
#include "sys/tree.h"

struct program {
    domainid_t pid;
    struct aos_chan chan;
    struct aos_chan notifier;  // send only
    LIST_ENTRY(program) link;
};

static LIST_HEAD(, program) clients = LIST_HEAD_INITIALIZER(&clients);

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

static void nameserver_urpc_handler(void *arg);


RPC_HANDLER(nameserver_bind)
{
    CAST_IN_MSG_EXACT_SIZE(msg, domainid_t);
    domainid_t pid = *msg;
    struct capref frame = in_cap;

    DEBUG_PRINTF("process %u bind\n", pid);

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
    err = ump_chan_register_recv(&b->chan.uc, get_default_waitset(),
                                 MKCLOSURE(nameserver_urpc_handler, b));
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

    LIST_INSERT_HEAD(&clients, b, link);
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

static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT];

/**
 * Nameserver URPC handler
 * @param arg  *struct client
 */
static void nameserver_urpc_handler(void *arg)
{
    errval_t err;
    struct program *client = arg;
    assert(client->chan.type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &client->chan.uc;

    UMP_RECV_DESERIALIZE(uc)
    UMP_RECV_NO_CAP

    // DEBUG_PRINTF("nameserver_urpc_handler: handling %u\n", type);
    UMP_ASSERT_DISPATCHER(rpc_handlers, NAMESERVICE_RPC_COUNT);
    UMP_DISPATCH_AND_REPLY_MAY_FAIL(&client->chan, rpc_handlers[recv_type], client)

    UMP_CLEANUP_AND_RE_REGISTER(uc, nameserver_urpc_handler, arg)
}

RPC_HANDLER(handle_register)
{
    struct program *server = arg;

    CAST_IN_MSG_AT_LEAST_SIZE(name, char);

    DEBUG_PRINTF("process %u register \"%s\"\n", server->pid, name);

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

    DEBUG_PRINTF("%u process deregister \"%s\"\n", server->pid, name);

    struct service *service = find_service(name);
    if (service == NULL) {
        return NAMESERVER_ERR_NOT_FOUND;
    }
    // TODO: check for pid
    RB_REMOVE(service_rb_tree, &services, service);
    free(service->name);
    free(service);
    return SYS_ERR_OK;
}

RPC_HANDLER(handle_lookup) {
    struct program *client = arg;
    errval_t err;

    CAST_IN_MSG_AT_LEAST_SIZE(name, char);

    DEBUG_PRINTF("process %u lookup \"%s\"\n", client->pid, name);

    struct service *service = find_service(name);
    if (service == NULL) {
        return NAMESERVER_ERR_NOT_FOUND;
    }

    struct capref frame;
    err = frame_alloc(&frame, UMP_CHAN_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }
    
    uint8_t *urpc_buffer;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_buffer,
                           UMP_CHAN_SHARED_FRAME_SIZE, frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP);
    }

    // Nameserver for zeroing the URPC frame
    memset(urpc_buffer, 0, UMP_CHAN_SHARED_FRAME_SIZE);

    err = paging_unmap(get_current_paging_state(), (void *)urpc_buffer);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_UNMAP);
    }
    // DEBUG_PRINTF("> process %u lookup \"%s\"\n", client->pid, name);

    struct program *server = service->program;
    MALLOC_WITH_SIZE(server_reply, struct ns_binding_notification, sizeof(domainid_t) + strlen(name) + 1);
    server_reply->pid = client->pid;
    memcpy(server_reply->name, name, strlen(name) + 1);
    err = aos_chan_send(&server->notifier, SERVER_BIND_UMP, frame, server_reply, sizeof(domainid_t) + strlen(name) + 1, false);
    if (err_is_fail(err)) {
        return err;
    }

    MALLOC_OUT_MSG(reply, domainid_t);
    *reply = server->pid;
    *out_cap = frame;
    return SYS_ERR_OK;

    // DEBUG_PRINTF(">> process %u lookup \"%s\"\n", client->pid, name);
}

// Empty entries are NULL since it's a global variable
static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT] = {
    [NAMESERVICE_REGISTER] = handle_register,
    [NAMESERVICE_DEREGISTER] = handle_deregister,
    [NAMESERVICE_LOOKUP] = handle_lookup,
};

struct aos_chan init_listener;

static void init_msg_handler(void *arg) {
    errval_t err;
    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->lc;

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type,
                                recv_buf, recv_size, helper, RE_REGISTER, FAILURE)

    // Call the handler, no reply to init
    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    err = nameserver_bind(NULL, recv_buf, recv_size, &reply_payload, &reply_size,
                recv_cap, &reply_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "nameserver_bind failed\n");
    }
    if (reply_payload != NULL) {
        free(reply_payload);
    }

    // Deserialization cleanup
    LMP_CLEANUP(err, helper)

FAILURE:
RE_REGISTER:
    LMP_RE_REGISTER(err, lc, init_msg_handler, arg)
}

int main(int argc, char *argv[])
{
    errval_t err;

    err = aos_chan_lmp_init_local(&init_listener, 32);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init init_listener\n");
        exit(EXIT_FAILURE);
    }

    err = aos_rpc_call(get_init_rpc(), RPC_REGISTER_AS_NAMESERVER, init_listener.lc.local_cap, NULL, 0, &init_listener.lc.remote_cap, NULL, 0);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to register as the nameserver\n");
        exit(EXIT_FAILURE);
    }
    assert(!capref_is_null(init_listener.lc.remote_cap));
    init_listener.lc.connstate = LMP_CONNECTED;

    err = lmp_chan_alloc_recv_slot(&init_listener.lc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to alloc recv slot on init_listener\n");
        exit(EXIT_FAILURE);
    }

    err = lmp_chan_register_recv(&init_listener.lc, get_default_waitset(), MKCLOSURE(init_msg_handler, &init_listener));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to listen on init_listener\n");
        exit(EXIT_FAILURE);
    }

    DEBUG_PRINTF("nameserver start\n");

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