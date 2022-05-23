/**
 * \file nameservice.h
 * \brief
 */
#include "stdio.h"
#include "stdlib.h"

#include "hashtable/hashtable.h"
#include "sys/queue.h"

#include <aos/lmp_handler_builder.h>
#include <aos/ump_handler_builder.h>
#include "internal.h"

// Declarations
static void ns_notification_handler(void *arg);


/// RPC to the nameserver

#define NAMESERVER_CHAN_BUF_LEN 32

struct aos_rpc ns_rpc = { .chan.type = AOS_CHAN_TYPE_UNKNOWN };

static struct aos_chan ns_listener;

static errval_t ensure_nameserver_chan(void)
{
    // If the channel is already setup, return OK
    if (ns_rpc.chan.type == AOS_CHAN_TYPE_UMP) {
        return SYS_ERR_OK;
    }

    assert(ns_rpc.chan.type == AOS_CHAN_TYPE_UNKNOWN);

    errval_t err;

    // Bind with the nameserver
    struct capref frame;
    while (true) {
        err = aos_rpc_call(get_init_rpc(), RPC_BIND_NAMESERVER, NULL_CAP, NULL, 0, &frame,
                           NULL, NULL);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                thread_yield();
                continue;
            } else {
                goto FAILURE_BIND_NAMESERVER_RPC;
            }
        } else {
            break;
        }
    }

    // The returned frame contains two UMP channels
    // First half for RPC
    // Second half for listener
    struct frame_identity frame_id;
    err = frame_identify(frame, &frame_id);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_FRAME_IDENTIFY);
        goto FAILURE_MAP_FRAME;
    }
    if (frame_id.bytes != UMP_CHAN_SHARED_FRAME_SIZE * 2) {
        err = err_push(err, LIB_ERR_UMP_INVALID_FRAME_SIZE);
        goto FAILURE_MAP_FRAME;
    }

    uint8_t *buf;
    err = paging_map_frame(get_current_paging_state(), (void **)&buf,
                           UMP_CHAN_SHARED_FRAME_SIZE * 2, frame);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_PAGING_MAP);
        goto FAILURE_MAP_FRAME;
    }

    // Setup NS RPC, without knowing nameserver's PID
    err = aos_chan_ump_init_from_buf(&ns_rpc.chan, buf, UMP_CHAN_CLIENT, 0);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE_SETUP_NS_RPC;
    }

    // Setup binding listening channel
    err = aos_chan_ump_init_from_buf(&ns_listener, buf + UMP_CHAN_SHARED_FRAME_SIZE,
                                     UMP_CHAN_SERVER, 0);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_UMP_CHAN_INIT);
        goto FAILURE_SETUP_LISTENER;
    }

    // Listen on the binding listener
    err = ump_chan_register_recv(&ns_listener.uc, get_default_waitset(),
                                 MKCLOSURE(ns_notification_handler, &ns_listener));
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
        goto FAILURE_START_LISTENING;
    }

    return SYS_ERR_OK;

FAILURE_START_LISTENING:
    aos_chan_destroy(&ns_listener);
    ns_listener.type = AOS_CHAN_TYPE_UNKNOWN;
FAILURE_SETUP_LISTENER:
    aos_chan_destroy(&ns_rpc.chan);
    ns_rpc.chan.type = AOS_CHAN_TYPE_UNKNOWN;
FAILURE_SETUP_NS_RPC:
    paging_unmap(get_current_paging_state(), buf);
FAILURE_MAP_FRAME:
    cap_destroy(frame);
FAILURE_BIND_NAMESERVER_RPC:
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
	DEBUG_PRINTF("nameservice_lookup enter\n");
    ENSURE_NAMESERVER_CHAN;
	DEBUG_PRINTF("nameservice_lookup exit\n");
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
 * @param arg  Expected to be &ns_listener.
 */
static void ns_notification_handler(void *arg)
{
    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->uc;

    errval_t err;

    UMP_RECV_DESERIALIZE(uc)
    UMP_RECV_CAP_IF_ANY(uc)

    switch ((enum ns_notification_identifier)recv_type) {
    case SERVER_BIND_LMP: {
        assert(recv_size >= sizeof(struct ns_binding_notification));
        struct ns_binding_notification *msg = (struct ns_binding_notification *)recv_buf;
        err = server_bind_lmp(msg->pid, msg->name);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_bind_lmp failed\n");
        }
    } break;
    case SERVER_BIND_UMP: {
        assert(recv_size >= sizeof(struct ns_binding_notification));
        assert(!capref_is_null(recv_cap));
        struct ns_binding_notification *msg = (struct ns_binding_notification *)recv_buf;
        err = server_bind_ump(msg->pid, msg->name, recv_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_bind_ump failed\n");
        }
    } break;
    case KILL_BY_PID:
        assert(recv_size == sizeof(domainid_t));
        err = server_kill_by_pid(*((domainid_t *)recv_buf));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: server_kill_by_pid failed\n");
        }
        err = client_kill_by_pid(*((domainid_t *)recv_buf));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ns_notification_handler: client_kill_by_pid failed\n");
        }
    default:
        DEBUG_PRINTF("ns_notification_handler: invalid recv_type %u\n", recv_type);
    }

    UMP_CLEANUP_AND_RE_REGISTER(uc, ns_notification_handler, arg)
}