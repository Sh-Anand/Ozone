//
// Created by Zikai Liu on 5/3/22.
//

#include <aos/ump_chan.h>
#include <aos/paging.h>
#include <aos/domain.h>
#include <string.h>

/**
 * \brief Initialise a new UMP channel
 *
 * \param uc  UMP channel
 * \param shared_frame  Shared frame of size UMP_CHAN_SHARED_FRAME_SIZE
 * \param client  Whether the current program is the client
 */
errval_t ump_chan_init(struct ump_chan *uc, struct capref shared_frame, bool client) {
    assert(uc != NULL);

    errval_t err;

    struct frame_identity urpc_frame_id;
    err = frame_identify(shared_frame, &urpc_frame_id);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_IDENTIFY);
    }
    if (urpc_frame_id.bytes != UMP_CHAN_SHARED_FRAME_SIZE) {
        return err_push(err, LIB_ERR_UMP_INVALID_FRAME_SIZE);
    }

    uint8_t *buf;
    err = paging_map_frame(get_current_paging_state(), (void **)&buf, UMP_CHAN_SHARED_FRAME_SIZE,
                           shared_frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP);
    }

    memset(buf, 0, UMP_CHAN_SHARED_FRAME_SIZE);

    return ump_chan_init_from_buf(uc, buf, client);
}

/**
 * \brief Initialise a new UMP channel from a mapped shared frame
 *
 * \param uc  UMP channel
 * \param zeroed_buf  Mapped memory region of the shared frame, should be memset to 0
 * \param client  Whether the current program is the client
 */
errval_t ump_chan_init_from_buf(struct ump_chan *uc, void *zeroed_buf, bool client) {
    assert(uc != NULL);

    errval_t err;

    uint8_t *b = zeroed_buf;

    err = ring_consumer_init(&uc->recv, client ? b : b + RING_BUFFER_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RING_CONSUMER_INIT);
    }

    err = ring_producer_init(&uc->send, client ? b + RING_BUFFER_SIZE : b);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RING_PRODUCER_INIT);
    }

    waitset_chanstate_init(&uc->recv_waitset, CHANTYPE_UMP_IN);

    return SYS_ERR_OK;
}

/**
 * \brief Destroy a UMP channel
 *
 * \param uc  UMP channel
 */
void ump_chan_destroy(struct ump_chan *uc) {
    waitset_chanstate_destroy(&uc->recv_waitset);
}