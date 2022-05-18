/**
 * \file nameservice.h
 * \brief
 */
#include "stdio.h"
#include "stdlib.h"

#include "hashtable/hashtable.h"
#include "sys/queue.h"

#include <aos/lmp_handler_builder.h>
#include "internal.h"

// Declarations
static void ns_notification_handler(void *arg);


/// RPC to the nameserver

#define NAMESERVER_CHAN_BUF_LEN 32

struct aos_rpc ns_rpc = { .chan.type = AOS_CHAN_TYPE_UNKNOWN };

static struct lmp_chan ns_listen_lc;  // single directional from nameserver only

enum ns_notification_identifier {
    SERVER_BIND_LMP,
    SERVER_BIND_UMP,
    KILL_BY_PID,
};

struct ns_binding_notification {
    domainid_t pid;
    char name[0];
};

static errval_t ensure_nameserver_chan(void)
{
    // If the channel is already setup, return OK
    if (ns_rpc.chan.type == AOS_CHAN_TYPE_LMP) {
        assert(ns_rpc.chan.lc.connstate == LMP_CONNECTED);
        return SYS_ERR_OK;
    }

    assert(ns_rpc.chan.type == AOS_CHAN_TYPE_UNKNOWN);

    errval_t err;

    // Create a new LMP channel
    ns_rpc.chan.type = AOS_CHAN_TYPE_LMP;
    err = lmp_chan_init_local(&ns_rpc.chan.lc, NAMESERVER_CHAN_BUF_LEN);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_INIT);
        goto FAILURE_SETUP_NAMESERVER_RPC;
    }

    // Bind with the nameserver
    err = aos_rpc_call(get_init_rpc(), RPC_BIND_NAMESERVER, ns_rpc.chan.lc.local_cap, NULL, 0,
                       &ns_rpc.chan.lc.remote_cap, NULL, NULL);
    if (err_is_fail(err)) {
        goto FAILURE_SETUP_NAMESERVER_RPC;
    }
    ns_rpc.chan.lc.connstate = LMP_CONNECTED;

    // Setup binding listening channel (single direction from nameserver to this program)
    err = lmp_chan_accept(&ns_listen_lc, NAMESERVER_CHAN_BUF_LEN, NULL_CAP);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
        goto FAILURE_SETUP_LISTENING_CHAN;
    }

    // Send the listen endpoint to the nameserver
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_SET_LISTEN_EP, ns_listen_lc.local_cap, NULL, 0, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_NAMESERVICE_SET_LISTEN_EP);
        goto FAILURE_SETUP_LISTENING_CHAN;
    }

    // Listen on the binding listener endpoint
    err = lmp_chan_alloc_recv_slot(&ns_listen_lc);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        goto FAILURE_SETUP_LISTENING_CHAN;
    }
    err = lmp_chan_register_recv(
        &ns_listen_lc, get_default_waitset(),
        MKCLOSURE(ns_notification_handler, &ns_listen_lc));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE_SETUP_LISTENING_CHAN;
    }

    return SYS_ERR_OK;

FAILURE_SETUP_LISTENING_CHAN:
    lmp_chan_destroy(&ns_listen_lc);
FAILURE_SETUP_NAMESERVER_RPC:
    lmp_chan_destroy(&ns_rpc.chan.lc);
    ns_rpc.chan.type = AOS_CHAN_TYPE_UNKNOWN;
    return err;
}

#define ENSURE_NAMESERVER_CHAN                                                           \
    do {                                                                                 \
        err = ensure_nameserver_chan();                                                  \
        if (err_is_fail(err)) {                                                          \
            return err;                                                                  \
        }                                                                                \
    } while (0)


/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_byts the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref rx_cap)
{
    return client_rpc(chan, message, bytes, response, response_bytes, tx_cap, rx_cap);
}


/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name,
                              nameservice_receive_handler_t recv_handler, void *st)
{
    errval_t err;
    ENSURE_NAMESERVER_CHAN;
    return server_register(name, recv_handler, st);
}


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name)
{
    errval_t err;
    ENSURE_NAMESERVER_CHAN;
    return server_deregister(name);
}


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *nschan)
{
    errval_t err;
    ENSURE_NAMESERVER_CHAN;
    return client_lookup_service(name, (struct client_side_chan **)nschan);
}


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries, should be freed outside (each entry and the whole)
 */
errval_t nameservice_enumerate(char *query, size_t *num, char ***result)
{
    errval_t err;
    ENSURE_NAMESERVER_CHAN;
    return client_enumerate_service(query, num, result);
}

/**
 * Handler for binding requests on the server side.
 * @param arg  Expected to be &binding_listen_lc.
 */
static void ns_notification_handler(void *arg)
{
    errval_t err;
    struct lmp_chan *lc = arg;

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type,
                                        recv_buf, recv_size, helper, RE_REGISTER, FAILURE)

    switch ((enum ns_notification_identifier)recv_type) {
    case SERVER_BIND_LMP:
    {
        struct ns_binding_notification *msg = (struct ns_binding_notification *)recv_buf;
        err = server_bind_lmp(msg->pid, msg->name);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_bind_lmp failed\n");
        }
    }
        break;
    case SERVER_BIND_UMP:
    {
        assert(!capref_is_null(recv_cap));
        struct ns_binding_notification *msg = (struct ns_binding_notification *)recv_buf;
        err = server_bind_ump(msg->pid, msg->name, recv_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_bind_ump failed\n");
        }
    }
        break;
    case KILL_BY_PID:
        err = server_kill_by_pid(*((domainid_t *) recv_buf));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_kill_by_pid failed\n");
        }
        err = client_kill_by_pid(*((domainid_t *) recv_buf));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: client_kill_by_pid failed\n");
        }
    default:
        DEBUG_PRINTF("ns_notification_handler: invalid recv_type %u\n", recv_type);
    }

    // Deserialization cleanup
    LMP_CLEANUP(err, helper)

FAILURE:
    // No special error handling is needed for now
RE_REGISTER:
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(ns_notification_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ns_notification_handler: error re-registering handler\n");
    }
}