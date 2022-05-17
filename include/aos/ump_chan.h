//
// Created by Zikai Liu on 5/3/22.
//

#ifndef AOS_UMP_CHAN_H
#define AOS_UMP_CHAN_H

#include <aos/capabilities.h>
#include <aos/waitset.h>
#include <aos/waitset_chan.h>
#include <ringbuffer/ringbuffer.h>
#include <assert.h>

__BEGIN_DECLS

#define UMP_CHAN_SHARED_FRAME_SIZE (RING_BUFFER_SIZE * 2)

/// A bidirectional UMP channel
struct ump_chan {
    struct waitset_chanstate recv_waitset;  ///< State belonging to waitset (for recv)
    struct ring_consumer recv;              ///< Ringbuffer receiver
    struct ring_producer send;              ///< Ringbuffer sender
};

enum UMP_CHAN_ROLE {
    UMP_CHAN_SERVER,
    UMP_CHAN_CLIENT
};

errval_t ump_chan_init(struct ump_chan *uc, struct capref zeroed_frame, enum UMP_CHAN_ROLE role);
errval_t ump_chan_init_from_buf(struct ump_chan *uc, void *zeroed_buf, enum UMP_CHAN_ROLE role);
void ump_chan_destroy(struct ump_chan *uc);

/**
 * \brief Transmit a payload through the UMP channel
 *
 * \param uc UMP channel
 * \param payload Payload to transmit
 * \param size Size of the payload
 */
static inline errval_t ump_chan_send(struct ump_chan *uc, const void *payload, size_t size) {
    return ring_producer_send(&uc->send, payload, size);
}

/**
 * \brief Retrieve an UMP payload, if possible
 *
 * \param uc UMP channel
 * \param payload UMP payload, malloc by this function and should be freed outside
 * \param size Payload size, to be filled by this function
 *
 * \return LIB_ERR_RING_NO_MSG if no message is available
 */
static inline errval_t ump_chan_recv(struct ump_chan *uc, void **payload, size_t *size) {
    return ring_consumer_recv_non_blocking(&uc->recv, payload, size);
}

/**
 * \brief Register an event handler to be notified when messages can be received
 *
 * A channel may only be registered with a single receive event handler on a single
 * waitset at any one time.
 *
 * \param uc UMP channel
 * \param ws Waitset
 * \param closure Event handler
 */
static inline errval_t ump_chan_register_recv(struct ump_chan *uc, struct waitset *ws,
                                              struct event_closure closure)
{
    return waitset_chan_register_polled(ws, &uc->recv_waitset, closure);
}

/**
 * \brief Cancel an event registration made with ump_chan_register_recv()
 *
 * \param uc UMP channel
 */
static inline errval_t ump_chan_deregister_recv(struct ump_chan *uc) {
    return waitset_chan_deregister(&uc->recv_waitset);
}

__END_DECLS

#endif
