//
// Created by Zikai Liu on 5/14/22.
//

#include <aos/aos.h>
#include "internal.h"

#define SERVER_SIDE_LMP_BUF_LEN 32

// Declarations
struct service;
struct server_side_chan;
static void delete_chan(struct server_side_chan *chan);
static AOS_CHAN_HANDLER(server_ump_handler);

struct service {
    char *name;  // hold the life cycle
    nameservice_receive_handler_t *recv_handler;
    void *st;
    struct server_side_chan *pending_lmp_chan;
    LIST_ENTRY(service) link;
};

static LIST_HEAD(, service) services = LIST_HEAD_INITIALIZER(&service);

struct server_side_chan {
    struct aos_chan chan;

    // Copy recv_handler and st since chan should keep alive after service is deregistered
    nameservice_receive_handler_t *recv_handler;
    void *st;

    domainid_t pid;  // pid of the other side
    LIST_ENTRY(server_side_chan) link;
};

static LIST_HEAD(, server_side_chan) chans = LIST_HEAD_INITIALIZER(&chans);

static errval_t create_service(const char *name,
                               nameservice_receive_handler_t recv_handler, void *st,
                               struct service **ret)
{
    struct service *service = malloc(sizeof(*service));
    if (service == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    service->name = strdup(name);
    service->recv_handler = recv_handler;
    service->pending_lmp_chan = NULL;
    service->st = st;
    *ret = service;
    LIST_INSERT_HEAD(&services, service, link);
    return SYS_ERR_OK;
}

static void delete_service(struct service *service)
{
    LIST_REMOVE(service, link);
    free(service->name);
    delete_chan(service->pending_lmp_chan);  // can handle NULL and UNKNOWN
    free(service);
}

static errval_t lookup_service(const char *name, struct service **ret)
{
    struct service *entry;
    LIST_FOREACH(entry, &services, link)
    {
        if (strcmp(entry->name, name) == 0) {
            *ret = entry;
            return SYS_ERR_OK;
        }
    }
    return LIB_ERR_NAMESERVICE_UNKNOWN_NAME;
}

// chan initialized as AOS_CHAN_TYPE_UNKNOWN, pid not initialized
// inserted into chans
static errval_t create_chan_from_service(struct service *service,
                                         struct server_side_chan **ret)
{
    struct server_side_chan *chan = malloc(sizeof(*chan));
    if (chan == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    chan->chan.type = AOS_CHAN_TYPE_UNKNOWN;
    chan->recv_handler = service->recv_handler;
    chan->st = service->st;
    LIST_INSERT_HEAD(&chans, chan, link);
    *ret = chan;
    return SYS_ERR_OK;
}

static void delete_chan(struct server_side_chan *chan)
{
    if (chan == NULL) {
        return;
    }
    LIST_REMOVE(chan, link);
    aos_chan_destroy(&chan->chan);
    free(chan);
}

errval_t server_register(const char *name, nameservice_receive_handler_t recv_handler,
                         void *st)
{
    errval_t err;

    // Create a new service record
    struct service *service;
    err = create_service(name, recv_handler, st, &service);
    if (err_is_fail(err)) {
        return err;
    }

//    // Create a pending LMP channel
//    err = create_pending_lmp_chan_on_service(service);
//    if (err_is_fail(err)) {
//        goto FAILURE_CREATE_PENDING_CHAN;
//    }
//    assert(service->pending_lmp_chan->chan.type == AOS_CHAN_TYPE_LMP);
//    assert(service->pending_lmp_chan->chan.lc.connstate == LMP_BIND_WAIT);

    // Register with nameserver
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_REGISTER,
                       NULL_CAP, name,
                       strlen(name) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        goto FAILURE_REGISTER;
    }

    return SYS_ERR_OK;

FAILURE_REGISTER:
//FAILURE_CREATE_PENDING_CHAN:
//    // aos_chan_destroy() in delete_chan() will call lmp_chan_destroy()
//    delete_chan(service->pending_lmp_chan);  // can handle NULL and do the free inside
    free(service);
    return err;
}

errval_t server_deregister(const char *name)
{
    errval_t err;

    // Look up the service locally first before the costly RPC call
    struct service *service;
    err = lookup_service(name, &service);
    if (err_is_fail(err)) {
        return err;
    }

    // Deregister with nameserver
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_DEREGISTER, NULL_CAP, name, strlen(name) + 1,
                       NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    delete_service(service);  // free inside

    return SYS_ERR_OK;
}

errval_t server_bind_lmp(domainid_t pid, const char *name)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t server_bind_ump(domainid_t pid, const char *name, struct capref frame)
{
    errval_t err;

    // Lookup the service
    struct service *service = NULL;
    err = lookup_service(name, &service);
    if (err_is_fail(err)) {
        return err;
    }

    // Create an UMP channel
    struct server_side_chan *chan = NULL;
    err = create_chan_from_service(service, &chan);
    if (err_is_fail(err)) {
        return err;
    }
    assert(chan->chan.type == AOS_CHAN_TYPE_UNKNOWN);
    err = aos_chan_ump_init(&chan->chan, frame, UMP_CHAN_SERVER, pid);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE_CREATE_UMP_CHAN;
    }

    // Listen on the UMP channel
    err = aos_chan_register_recv(&chan->chan, get_default_waitset(),
                                 server_ump_handler, chan);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE_REGISTER_RECV;
    }

    return SYS_ERR_OK;

FAILURE_REGISTER_RECV:
    aos_chan_destroy(&chan->chan);
FAILURE_CREATE_UMP_CHAN:
    delete_chan(chan);
    return err;
}

struct aos_chan *server_lookup_chan(domainid_t pid) {
    struct server_side_chan *c;
    LIST_FOREACH(c, &chans, link) {
        if (c->pid == pid) {
            return &c->chan;
        }
    }
    return NULL;
}

/**
 * UMP handler.
 * @param arg  Pointer to a struct server_side_chan
 */
static AOS_CHAN_HANDLER(server_ump_handler)
{
    struct server_side_chan *chan = arg;
    assert(chan->chan.type == AOS_CHAN_TYPE_UMP);

    // XXX: trick to pass PID to the handler over the end of recv_buf
    void *new_in_payload = malloc(in_size + sizeof(domainid_t));
    memcpy(new_in_payload, in_payload, in_size);
    CAST_DEREF(domainid_t, new_in_payload, in_size) = chan->pid;

    chan->recv_handler(chan->st, new_in_payload, in_size, out_payload, out_size, in_cap, out_cap);

    *free_out_payload = false;
    return SYS_ERR_OK;
}

errval_t server_kill_by_pid(domainid_t pid)
{
    errval_t err;
    struct server_side_chan *c, *tmp;
    LIST_FOREACH_SAFE(c, &chans, link, tmp) {
        if (c->pid == pid) {
            err = aos_chan_deregister_recv(&c->chan);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_CHAN_DEREGISTER_RECV);
            }

            aos_chan_destroy(&c->chan);

            delete_chan(c);
        }
    }
    return SYS_ERR_OK;
}