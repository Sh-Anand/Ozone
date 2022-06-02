//
// Created by Zikai Liu on 5/29/22.
//

#ifndef AOS_RPC_H
#define AOS_RPC_H

#include <aos/aos.h>
#include <aos/lmp_chan.h>
#include <aos/ump_chan.h>

enum aos_chan_type {
    AOS_CHAN_TYPE_UNKNOWN,
    AOS_CHAN_TYPE_LMP,
    AOS_CHAN_TYPE_UMP,
    AOS_CHAN_TYPE_ECHO,
};

typedef uint8_t rpc_identifier_t;

enum {
    RPC_ACK = 0,
    RPC_ERR
};

#define RPC_IDENTIFIER_USER_START 8
#define RPC_IDENTIFIER_USER_END ((1U << (sizeof(rpc_identifier_t) * 8 - 1)) - 1)

typedef errval_t (*aos_chan_handler_t)(void *arg, rpc_identifier_t identifier,
                                       void *in_payload, size_t in_size,
                                       struct capref in_cap, void **out_payload,
                                       size_t *out_size, struct capref *out_cap,
                                       bool *free_out_payload, bool *re_register);

#define AOS_CHAN_HANDLER(name)                                                           \
    errval_t name(void *arg, rpc_identifier_t identifier, void *in_payload,              \
                  size_t in_size, struct capref in_cap, void **out_payload,              \
                  size_t *out_size, struct capref *out_cap, bool *free_out_payload,      \
                  bool *re_register)

struct aos_chan {
    enum aos_chan_type type;
    union {
        struct lmp_chan lc;
        struct ump_chan uc;
    };
    struct thread_mutex mutex;  // make one respond associated with one request
    aos_chan_handler_t handler;
    void *arg;
};

struct aos_rpc {
    struct aos_chan chan;
};

#define OFFSET(ptr, offset_in_byte) ((uint8_t *)(ptr) + (offset_in_byte))

#define CAST_DEREF(type, ptr, offset_in_byte) (*((type *)OFFSET(ptr, offset_in_byte)))

errval_t rpc_lmp_put_cap(struct lmp_chan *lc, struct capref cap);

/**
 * \brief Initialize an aos_chan with a disconnected LMP channel.
 */
void aos_chan_lmp_init(struct aos_chan *chan);

/**
 * \brief Initialize an aos_chan with LMP type by accepting an endpoint.
 * \note  This function will send the local endpoint and wait for ack (blocking).
 */
errval_t aos_chan_lmp_accept(struct aos_chan *chan, size_t buflen_words,
                             struct capref endpoint);

/**
 * \brief Initialize an aos_chan with LMP type by creating local endpoint.
 * \note  This function will NOT start listening on the channel waiting for binding.
 *        Even if message handling is not needed, to setup the binding, call
 *        aos_chan_register_recv with NULL handler.
 */
errval_t aos_chan_lmp_init_local(struct aos_chan *chan, size_t buflen_words);

/**
 * \brief Initialize an aos_chan with UMP type from a zeroed shared frame.
 */
errval_t aos_chan_ump_init(struct aos_chan *chan, struct capref zeroed_frame,
                           enum UMP_CHAN_ROLE role, domainid_t pid);

/**
 * \brief Initialize an aos_chan with UMP type from a zeroed shared buffer.
 */
errval_t aos_chan_ump_init_from_buf(struct aos_chan *chan, void *zeroed_buf,
                                    enum UMP_CHAN_ROLE role, domainid_t pid);

/**
 * \brief Destroy an aos_chan struct. Call LMP/UMP destroy function based on type.
 */
void aos_chan_destroy(struct aos_chan *chan);

/**
 * \brief Register an event handler to be notified when messages can be received
 * \note  handler can be NULL. In that case, messages are consumed but discard. For LMP
 *        channel, the binding process is still performed.
 */
errval_t aos_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                                aos_chan_handler_t handler, void *arg);

/**
 * \brief Cancel an event registration made with aos_chan_register_recv()
 */
errval_t aos_chan_deregister_recv(struct aos_chan *chan);

/**
 * \brief Check if a channel has data to receive
 */
bool aos_chan_can_recv(struct aos_chan *chan);

/**
 * \brief Unified interface to make an RPC call.
 * \note  ret_buf should be freed outside.
 */
errval_t aos_chan_call(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref call_cap, const void *call_buf, size_t call_size,
                       struct capref *ret_cap, void **ret_buf, size_t *ret_size);


/**
 * \brief Unified interface to send a message
 */
errval_t aos_chan_send(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref cap, const void *buf, size_t size, bool non_blocking);

/**
 * \brief Reply a successful RPC call.
 */
errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, const void *buf,
                      size_t size);

/**
 * \brief Reply a failed RPC call.
 */
errval_t aos_chan_nack(struct aos_chan *chan, errval_t err);


/**
 * \brief Check if a aos_chan is connected.
 */
bool aos_chan_is_connected(struct aos_chan *chan);


/**
 * \brief Initialize an aos_rpc struct. chan is set to AOS_CHAN_TYPE_UNKNOWN
 */
void aos_rpc_init(struct aos_rpc *rpc);

/**
 * \brief Destroy an aos_rpc struct.
 */
void aos_rpc_destroy(struct aos_rpc *rpc);

/**
 * \brief Unified interface to make an RPC call.
 * \note  ret_buf should be freed outside.
 */
static inline errval_t aos_rpc_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                                    struct capref call_cap, const void *call_buf,
                                    size_t call_size, struct capref *ret_cap,
                                    void **ret_buf, size_t *ret_size)
{
    errval_t err;
    do {
        err = aos_chan_call(&rpc->chan, identifier, call_cap, call_buf, call_size, ret_cap,
                      ret_buf, ret_size);
        if (err == MON_ERR_RETRY) {
            thread_yield();
        } else {
            break;
        }
    } while (1);
    return err;
}

#endif  // AOS_RPC_H
