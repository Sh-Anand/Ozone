//
// Created by Zikai Liu on 5/3/22.
//

#include "nameserver.h"
#include "aos/aos_rpc.h"
#include "sys/queue.h"
#include "spawn/spawn.h"
#include <aos/lmp_handler_builder.h>
#include "aos/rpc_handler_builder.h"

#define NAMESERVER_EP_BUF_LEN 16

struct client {
    domainid_t pid;
    struct aos_chan chan;
    struct aos_chan notifier;  // send only
    LIST_ENTRY(client) link;
};

static LIST_HEAD(, client) clients = LIST_HEAD_INITIALIZER(&clients);

static void nameserver_rpc_handler(void *arg);

errval_t nameserver_bind(domainid_t pid, struct capref client_ep, struct capref *reply_ep)
{
    errval_t err;

    struct client *b = malloc(sizeof(*b));
    if (b == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    assert(spawn_get_core(pid) == disp_get_core_id());
    b->pid = pid;
    b->chan.type = AOS_CHAN_TYPE_LMP;
    err = lmp_chan_accept(&b->chan.lc, NAMESERVER_EP_BUF_LEN, client_ep);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_INIT);
        goto FAILURE;
    }
    err = lmp_chan_register_recv(&b->chan.lc, get_default_waitset(),
                                 MKCLOSURE(nameserver_rpc_handler, b));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE;
    }
    b->notifier.type = AOS_CHAN_TYPE_LMP;
    lmp_chan_init(&b->notifier.lc);
    b->notifier.lc.remote_cap = NULL_CAP;

    LIST_INSERT_HEAD(&clients, b, link);
    *reply_ep = b->chan.lc.local_cap;

    return SYS_ERR_OK;

FAILURE:
    free(b);
    return err;
}

static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT];

static void nameserver_rpc_handler(void *arg)
{
    errval_t err;
    struct client *client = arg;
    assert(client->chan.type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &client->chan.lc;
    assert(lc->connstate == LMP_CONNECTED);

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type, recv_buf,
                                recv_size, helper, RE_REGISTER, FAILURE)

    // Sanity check, LMP can only accept RPC exposed to the user
    if (recv_type >= NAMESERVICE_RPC_COUNT || rpc_handlers[recv_type] == NULL) {
        DEBUG_PRINTF("nameserver_rpc_handler: invalid recv_type %u\n", recv_type);
        aos_chan_nack(&client->chan, LIB_ERR_RPC_INVALID_MSG);
        goto RE_REGISTER;
    }

    // LMP can only accept RPC exposed to the user
    LMP_DISPATCH_AND_REPLY_MAY_FAIL(err, &client->chan, client, rpc_handlers[recv_type],
                                    recv_cap)

    // Deserialization cleanup
    LMP_CLEANUP(err, helper)

FAILURE:
RE_REGISTER:
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(nameserver_rpc_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "nameserver_rpc_handler: error re-registering handler\n");
    }
}

#define ASSERT_INCOMING_EP_CAP                                                           \
    do {                                                                                 \
        if (capref_is_null(in_cap)) {                                                    \
            return ERR_INVALID_ARGS;                                                     \
        }                                                                                \
        struct capability c;                                                             \
        err = cap_direct_identify(in_cap, &c);                                           \
        if (err_is_fail(err)) {                                                          \
            return err_push(err, LIB_ERR_CAP_IDENTIFY);                                  \
        }                                                                                \
        if (c.type != ObjType_EndPointLMP) {                                             \
            return ERR_INVALID_ARGS;                                                     \
        }                                                                                \
    } while (0)

RPC_HANDLER(handle_set_listen_ep)
{
    struct client *client = arg;
    errval_t err;

    ASSERT_INCOMING_EP_CAP;
    ASSERT_ZERO_IN_SIZE;

    // Destroy the original endpoint if not NULL_CAP
    assert(client->notifier.type == AOS_CHAN_TYPE_LMP);
    if (!capref_is_null(client->notifier.lc.remote_cap)) {
        err = cap_destroy(client->notifier.lc.remote_cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }
    }

    // Set the notifier endpoint
    client->notifier.lc.remote_cap = in_cap;
    return SYS_ERR_OK;
}

RPC_HANDLER(handle_register)
{
    struct client *client = arg;
    errval_t err;

    ASSERT_INCOMING_EP_CAP;
    CAST_IN_MSG_NO_CHECK(name, char);
}

// Empty entries are NULL since it's a global variable
static rpc_handler_t const rpc_handlers[NAMESERVICE_RPC_COUNT] = {
    [NAMESERVICE_SET_LISTEN_EP] = handle_set_listen_ep,
    [NAMESERVICE_REGISTER] = handle_register,
};