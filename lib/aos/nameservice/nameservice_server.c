//
// Created by Zikai Liu on 5/14/22.
//

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/lmp_handler_builder.h>
#include "internal.h"

#define SERVER_SIDE_LMP_BUF_LEN 32

// Declarations
struct service;
struct server_side_chan;
static void delete_chan(struct server_side_chan *chan);
static void server_lmp_handler(void *arg);
static void server_ump_handler(void *arg);

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

static errval_t create_pending_lmp_chan_on_service(struct service *service)
{
    errval_t err;
    service->pending_lmp_chan = NULL;
    err = create_chan_from_service(service, &service->pending_lmp_chan);
    if (err_is_fail(err)) {
        return err;
    }
    service->pending_lmp_chan->chan.type = AOS_CHAN_TYPE_LMP;
    err = lmp_chan_init_local(&service->pending_lmp_chan->chan.lc,
                              SERVER_SIDE_LMP_BUF_LEN);
    if (err_is_fail(err)) {
        delete_chan(service->pending_lmp_chan);
        return err_push(err, LIB_ERR_LMP_CHAN_INIT_LOCAL);
    }
    return SYS_ERR_OK;
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

    // Create a pending LMP channel
    err = create_pending_lmp_chan_on_service(service);
    if (err_is_fail(err)) {
        goto FAILURE_CREATE_PENDING_CHAN;
    }
    assert(service->pending_lmp_chan->chan.type == AOS_CHAN_TYPE_LMP);
    assert(service->pending_lmp_chan->chan.lc.connstate == LMP_BIND_WAIT);

    // Register with nameserver
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_REGISTER,
                       service->pending_lmp_chan->chan.lc.local_cap, name,
                       strlen(name) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        goto FAILURE_REGISTER;
    }

    return SYS_ERR_OK;

FAILURE_REGISTER:
FAILURE_CREATE_PENDING_CHAN:
    // aos_chan_destroy() in delete_chan() will call lmp_chan_destroy()
    delete_chan(service->pending_lmp_chan);  // can handle NULL and do the free inside
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
    errval_t err;

    // Lookup the service
    struct service *service = NULL;
    err = lookup_service(name, &service);
    if (err_is_fail(err)) {
        return err;
    }

    // Sanity check
    struct server_side_chan *chan = service->pending_lmp_chan;
    assert(chan != NULL);
    assert(chan->chan.type == AOS_CHAN_TYPE_LMP);
    assert(chan->chan.lc.connstate == LMP_BIND_WAIT);

    chan->pid = pid;
    // The channel becomes effective now, and it is already in chans at creation time

    // Listen on the pending channel, the client will send its endpoint in the channel
    err = lmp_chan_alloc_recv_slot(&chan->chan.lc);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }
    err = lmp_chan_register_recv(&chan->chan.lc, get_default_waitset(),
                                 MKCLOSURE(server_lmp_handler, chan));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
    }

    // Create another pending LMP channel
    err = create_pending_lmp_chan_on_service(service);
    if (err_is_fail(err)) {
        goto FAILURE_CREATE_PENDING_CHAN;
    }
    assert(service->pending_lmp_chan->chan.type == AOS_CHAN_TYPE_LMP);
    assert(service->pending_lmp_chan->chan.lc.connstate == LMP_BIND_WAIT);

    // Register the new pending endpoint with nameserver
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_REFILL_LMP_ENDPOINT,
                       service->pending_lmp_chan->chan.lc.local_cap, name,
                       strlen(name) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        goto FAILURE_REGISTER;
    }

    return SYS_ERR_OK;

FAILURE_REGISTER:
FAILURE_CREATE_PENDING_CHAN:
    // aos_chan_destroy() in delete_chan() will call lmp_chan_destroy()
    delete_chan(service->pending_lmp_chan);  // can handle NULL and do the free inside
    return err;
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
    chan->chan.type = AOS_CHAN_TYPE_UMP;
    err = ump_chan_init(&chan->chan.uc, frame, false);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE_CREATE_UMP_CHAN;
    }

    // Listen on the UMP channel
    err = ump_chan_register_recv(&chan->chan.uc, get_default_waitset(),
                                 MKCLOSURE(server_ump_handler, chan));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE_REGISTER_RECV;
    }

    return SYS_ERR_OK;

FAILURE_REGISTER_RECV:
    chan->chan.type = AOS_CHAN_TYPE_UNKNOWN;
    ump_chan_destroy(&chan->chan.uc);
FAILURE_CREATE_UMP_CHAN:
    delete_chan(chan);
    return err;
}

/**
 * LMP handler.
 * @param arg  Pointer to a struct server_side_chan
 */
static void server_lmp_handler(void *arg)
{
    errval_t err;
    struct server_side_chan *chan = arg;
    assert(chan->chan.type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->chan.lc;

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_HANDLER_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type,
                                        recv_buf, recv_size, helper, RE_REGISTER, FAILURE)

    // If the channel is not setup yet, set it up
    if (lc->connstate == LMP_BIND_WAIT) {
        LMP_HANDLER_TRY_SETUP_BINDING(err, lc, recv_cap, FAILURE)

        // Ack
        err = aos_chan_ack(&chan->chan, NULL_CAP, NULL, 0);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "server_lmp_handler (binding): aos_chan_ack failed\n");
            goto FAILURE;
        }
        goto RE_REGISTER;
    }

    // Identifier is not used and always set as RPC_USER for nameservice_chan
    assert(recv_type == IDENTIFIER_NORMAL);

    // Call the handler
    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    chan->recv_handler(chan->st, recv_buf, recv_size, &reply_payload, &reply_size,
                       recv_cap, &reply_cap);

    // Reply
    err = aos_chan_ack(&chan->chan, reply_cap, reply_payload, reply_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_lmp_handler: failed to reply\n");
    }

    // Clean up
    if (reply_payload != NULL) {
        free(reply_payload);
    }

    // Deserialization cleanup
    LMP_HANDLER_CLEANUP(err, helper)

FAILURE:
RE_REGISTER:
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(server_lmp_handler, arg /* not chan */));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_lmp_handler: error re-registering handler\n");
    }
}

/**
 * UMP handler.
 * @param arg  Pointer to a struct server_side_chan
 */
static void server_ump_handler(void *arg)
{
    struct server_side_chan *chan = arg;
    assert(chan->chan.type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->chan.uc;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;

    errval_t err = ump_chan_recv(uc, (void **)&recv_payload, &recv_size);
    if (err == LIB_ERR_RING_NO_MSG) {
        goto RE_REGISTER;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_ump_handler: ring_consumer_recv failed\n");
        goto RE_REGISTER;
    }

    rpc_identifier_t recv_type = *((rpc_identifier_t *)recv_payload);
    (void)recv_type;  // XXX: recv_type is not used for now

    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    chan->recv_handler(chan->st, recv_payload + sizeof(rpc_identifier_t),
                       recv_size - sizeof(rpc_identifier_t), &reply_payload, &reply_size,
                       NULL_CAP, &reply_cap);

    assert(capref_is_null(reply_cap));  // cannot send cap for now


    err = ump_prefix_identifier(&reply_payload, &reply_size, RPC_ACK);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_ump_handler: ump_prefix_identifier failed\n");
        goto FREE_REPLY_PAYLOAD;  // on failure, reply_payload is not freed inside
    }

    err = ump_chan_send(uc, reply_payload, reply_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_ump_handler: failed to reply\n");
    }

FREE_REPLY_PAYLOAD:
    free(reply_payload);
    free(recv_payload);
RE_REGISTER:
    err = ump_chan_register_recv(uc, get_default_waitset(),
                                 MKCLOSURE(server_ump_handler, arg /* not chan */));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "server_ump_handler: error re-registering handler");
    }
}

errval_t server_kill_by_pid(domainid_t pid)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}