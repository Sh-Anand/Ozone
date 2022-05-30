//
// Created by Zikai Liu on 5/29/22.
//

#include <rpc_priv.h>
#include <aos/paging.h>
#include <aos/domain.h>
#include <string.h>

typedef uint8_t lmp_single_msg_size_t;

#define LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE                                                  \
    (LMP_MSG_LENGTH * sizeof(uintptr_t) - sizeof(lmp_single_msg_size_t)                  \
     - sizeof(rpc_identifier_t))

STATIC_ASSERT(LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE
                  <= (1 << (sizeof(lmp_single_msg_size_t) * 8)),
              "lmp_single_msg_size_t too small");

errval_t rpc_lmp_serialize(rpc_identifier_t identifier, struct capref cap, const void *buf,
                       size_t size, uintptr_t ret_payload[LMP_MSG_LENGTH],
                       struct capref *ret_cap, struct lmp_helper *helper)
{
    if (buf == NULL && size != 0) {
        return ERR_INVALID_ARGS;
    }
    errval_t err;
    helper->payload_frame = NULL_CAP;
    helper->mapped_frame = NULL;

    if (size <= LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE) {  // buffer fits in the remaining space
        CAST_DEREF(lmp_single_msg_size_t, ret_payload, 0) = (lmp_single_msg_size_t)size;
        CAST_DEREF(rpc_identifier_t, ret_payload, sizeof(lmp_single_msg_size_t))
            = identifier;
        memcpy(
            OFFSET(ret_payload, sizeof(lmp_single_msg_size_t) + sizeof(rpc_identifier_t)),
            buf, size);
        *ret_cap = cap;

    } else {
        // Buffer doesn't fit, make and map frame cap
#if 1
        DEBUG_PRINTF("rpc_lmp_serialize: alloc frame\n");
#endif

        size_t rounded_size = ROUND_UP(size + sizeof(size_t) + sizeof(rpc_identifier_t),
                                       BASE_PAGE_SIZE);

        struct capref frame_cap;
        err = frame_alloc(&frame_cap, rounded_size, NULL);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_FRAME_ALLOC);
        }

        uint8_t *addr;
        err = paging_map_frame(get_current_paging_state(), (void **)&addr, rounded_size,
                               frame_cap);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_PAGING_MAP);
        }

        CAST_DEREF(size_t, addr, 0) = size;
        // Put identifier before actual payload, consistent with single message
        CAST_DEREF(rpc_identifier_t, addr, sizeof(size_t)) = identifier;
        memcpy(OFFSET(addr, sizeof(size_t) + sizeof(rpc_identifier_t)), buf, size);

        // Replace the size and the identifier
        CAST_DEREF(lmp_single_msg_size_t, ret_payload, 0) = 0;
        CAST_DEREF(rpc_identifier_t, ret_payload, sizeof(lmp_single_msg_size_t))
            = RPC_MSG_IN_FRAME;

        *ret_cap = frame_cap;

        helper->payload_frame = frame_cap;
        helper->mapped_frame = addr;
    }

    return SYS_ERR_OK;
}

errval_t rpc_lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref *recv_cap_ptr,
                         rpc_identifier_t *ret_type, uint8_t **ret_buf, size_t *ret_size,
                         struct lmp_helper *helper)
{
    errval_t err;
    helper->payload_frame = NULL_CAP;
    helper->mapped_frame = NULL;

    rpc_identifier_t type = CAST_DEREF(rpc_identifier_t, recv_msg->words,
                                       sizeof(lmp_single_msg_size_t));
    uint8_t *buf;
    size_t size;

    uint8_t *frame_payload = NULL;

    if (type == RPC_MSG_IN_FRAME) {
        assert(!capref_is_null(*recv_cap_ptr));

#if 1
        DEBUG_PRINTF("rpc_lmp_deserialize: trying to map received frame in local space\n");
#endif

        struct frame_identity frame_id;
        err = frame_identify(*recv_cap_ptr, &frame_id);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_FRAME_IDENTIFY);
        }

        err = paging_map_frame(get_current_paging_state(), (void **)&frame_payload,
                               frame_id.bytes, *recv_cap_ptr);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_MAP);
        }

        size = CAST_DEREF(size_t, frame_payload, 0);
        type = CAST_DEREF(rpc_identifier_t, frame_payload, sizeof(size_t));  // replace
        buf = OFFSET(frame_payload, sizeof(size_t) + sizeof(rpc_identifier_t));

        helper->payload_frame = *recv_cap_ptr;
        helper->mapped_frame = frame_payload;

        *recv_cap_ptr = NULL_CAP;  // no cap is actually received
    } else {
        size = (size_t)CAST_DEREF(lmp_single_msg_size_t, recv_msg->words, 0);
        // type is already decoded
        buf = OFFSET(recv_msg->words,
                     sizeof(lmp_single_msg_size_t) + sizeof(rpc_identifier_t));
    }

    *ret_type = type;
    *ret_buf = buf;
    *ret_size = size;
    return SYS_ERR_OK;
}

errval_t rpc_lmp_cleanup(struct lmp_helper *helper)
{
    if (helper->mapped_frame != NULL) {
        assert(!capref_is_null(helper->payload_frame));

        errval_t err;
        err = paging_unmap(get_current_paging_state(), helper->mapped_frame);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_UNMAP);
        }
        err = cap_destroy(helper->payload_frame);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

    } else {
        assert(capref_is_null(helper->payload_frame));
    }
    return SYS_ERR_OK;
}

errval_t lmp_try_send(struct lmp_chan *lc, uintptr_t *send_words, struct capref send_cap,
                      bool non_blocking)
{
    errval_t err;
    while (true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, send_cap, send_words[0],
                             send_words[1], send_words[2], send_words[3]);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                if (non_blocking) {
                    return err;  // expose transient error directly
                } else {
                    thread_yield();
                }
            } else {
                return err_push(err, LIB_ERR_LMP_CHAN_SEND);
            }
        } else {
            return SYS_ERR_OK;
        }
    }
}

errval_t lmp_try_recv(struct lmp_chan *lc, struct lmp_recv_msg *recv_msg,
                      struct capref *recv_cap)
{
    errval_t err;
    while (true) {
        err = lmp_chan_recv(lc, recv_msg, recv_cap);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_NO_LMP_MSG) {
                thread_yield();
            } else {
                return err_push(err, LIB_ERR_LMP_CHAN_RECV);
            }
        } else {
            return SYS_ERR_OK;
        }
    }
}

errval_t rpc_lmp_send(struct lmp_chan *lc, rpc_identifier_t identifier, struct capref cap,
                      const void *buf, size_t size, bool non_blocking)
{
    errval_t err;
    uintptr_t send_words[LMP_MSG_LENGTH];
    struct capref send_cap;
    struct lmp_helper send_helper;

    err = rpc_lmp_serialize(identifier, cap, buf, size, send_words, &send_cap,
                            &send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    // Send
    err = lmp_try_send(lc, send_words, send_cap, non_blocking);
    if (err_is_fail(err)) {
        return err;  // expose transient error directly
    }

    // Clean up
    err = rpc_lmp_cleanup(&send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CLEANUP);
    }

    return SYS_ERR_OK;
}

errval_t rpc_lmp_call(struct aos_chan *chan, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size,
                      bool no_lock)
{
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->lc;

    errval_t err;

    if (capref_is_null(lc->endpoint->recv_slot)) {
        // This can happen when the current send is triggered by a slot refill
        // In this case, slot allocator is willing to give out a slot as its internal
        // refill flag is set
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("rpc_lmp_call: lmp_chan_alloc_recv_slot failed (case 2)\n");
            return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        }
    }

    uintptr_t send_words[LMP_MSG_LENGTH];
    struct capref send_cap;
    struct lmp_helper send_helper;

    // Serialization
    // We do not use mutex to protect send since it may trigger recursive RPC
    err = rpc_lmp_serialize(identifier, call_cap, call_buf, call_size, send_words,
                            &send_cap, &send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap = NULL_CAP;

    THREAD_MUTEX_ENTER_IF(&chan->mutex, !no_lock)
    {
        // Send
        err = lmp_try_send(lc, send_words, send_cap, false);
        if (err_is_fail(err)) {
            THREAD_MUTEX_BREAK;
        }

        // Receive acknowledgement and/or return message
        err = lmp_try_recv(lc, &recv_msg, &recv_cap);
        if (err_is_fail(err)) {
            THREAD_MUTEX_BREAK;
        }
    }
    THREAD_MUTEX_EXIT_IF(&chan->mutex, !no_lock)
    if (err_is_fail(err)) {
        return err;
    }

    // Refill recv cap if the slot is consumed
    if (!capref_is_null(recv_cap)) {
        lc->endpoint->recv_slot = NULL_CAP;  // clear it to trigger the force refill above
        err = lmp_chan_alloc_recv_slot(lc);  // this may trigger another RPC call
        if (err_is_fail(err)) {
            DEBUG_PRINTF("rpc_lmp_call: lmp_chan_alloc_recv_slot failed (case 1)\n");
            return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
        }
    }

    rpc_identifier_t recv_type;
    uint8_t *recv_buf;
    size_t recv_size;
    struct lmp_helper recv_helper;

    err = rpc_lmp_deserialize(&recv_msg, &recv_cap, &recv_type, &recv_buf, &recv_size,
                              &recv_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_DESERIALIZE);
    }

    if (recv_type == RPC_ACK) {
        if (ret_buf) {
            *ret_buf = malloc(recv_size);
            memcpy(*ret_buf, recv_buf, recv_size);
        }

        if (ret_size) {
            *ret_size = recv_size;
        }

        if (!capref_is_null(recv_cap)) {
            if (ret_cap) {
                *ret_cap = recv_cap;
            } else {
                DEBUG_PRINTF("rpc_lmp_call: received a cap but is given up!\n");
            }
        }
        err = SYS_ERR_OK;

    } else if (recv_type == RPC_ERR) {
        err = *((errval_t *)recv_buf);

    } else {
        DEBUG_PRINTF("rpc_lmp_call: unknown recv_type %u\n", recv_type);
        err = LIB_ERR_RPC_INVALID_MSG;
    }


    // Clean up (don't touch err)
    errval_t err2 = rpc_lmp_cleanup(&send_helper);
    if (err_is_fail(err2)) {
        DEBUG_ERR(err2, "rpc_lmp_call: failed to clean up\n");
    }
    err2 = rpc_lmp_cleanup(&recv_helper);
    if (err_is_fail(err2)) {
        DEBUG_ERR(err2, "rpc_lmp_call: failed to clean up\n");
    }

    return err;
}

errval_t rpc_lmp_put_cap(struct lmp_chan *lc, struct capref cap)
{
    assert(!capref_is_null(cap));
    return rpc_lmp_send(lc, RPC_PUT_CAP, cap, NULL, 0, false);
}

static errval_t rpc_lmp_ack(struct lmp_chan *lc, struct capref cap, const void *buf, size_t size)
{
    return rpc_lmp_send(lc, RPC_ACK, cap, buf, size, false);
}

static errval_t rpc_lmp_nack(struct lmp_chan *lc, errval_t err)
{
    return rpc_lmp_send(lc, RPC_ERR, NULL_CAP, &err, sizeof(errval_t), false);
}

static void rpc_lmp_generic_handler(void *arg)
{
    bool re_register = true;
    errval_t err;

    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->lc;

    /// Receive the message and cap, refill the recv slot, deserialize

    struct lmp_recv_msg recv_raw_msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;

    /* Try to receive a message */
    err = lmp_chan_recv(lc, &recv_raw_msg, &recv_cap);
    if (err_is_fail(err)) {
        if (lmp_err_is_transient(err)) {
            goto RE_REGISTER;
        }
        DEBUG_ERR(err, "%s: unhandled error from lmp_chan_recv\n", __func__);
        goto FAILURE;
    }

    /* Refill the recv_cap slot if the recv slot is used (received a recv_cap) */
    if (!capref_is_null(recv_cap)) {
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "%s: fail to alloc new slot\n", __func__);
            goto FAILURE;
        }
    }

    /* Deserialize */
    rpc_identifier_t recv_identifier;
    uint8_t *recv_buf;
    size_t recv_size;
    struct lmp_helper helper;
    err = rpc_lmp_deserialize(&recv_raw_msg, &recv_cap, &recv_identifier, &recv_buf,
                              &recv_size, &helper);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_LMP_SERIALIZE);
        DEBUG_ERR(err, "%s: fail to deserialize\n", __func__);
        goto FAILURE;
    }

    /// If the channel is not setup yet, set it up

    if (lc->connstate == LMP_BIND_WAIT) {
        assert(lc->connstate == LMP_BIND_WAIT);

        /* Check the received endpoint */
        if (capref_is_null(recv_cap)) {
            DEBUG_PRINTF("%s (binding): no cap received\n", __func__);
            goto FAILURE;
        }
        struct capability capability;
        err = cap_direct_identify(recv_cap, &capability);
        if (capref_is_null(recv_cap)) {
            DEBUG_ERR(err, "%s (binding): cap_direct_identify failed\n", __func__);
            goto FAILURE;
        }
        if (capability.type != ObjType_EndPointLMP) {
            DEBUG_ERR(err, "%s (binding): recv cap type %u\n", __func__, capability.type);
            goto FAILURE;
        }
        lc->remote_cap = recv_cap;
        lc->connstate = LMP_CONNECTED;

        /* Ack */
        err = rpc_lmp_ack(lc, NULL_CAP, NULL, 0);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_lmp_handler (binding): aos_chan_ack failed\n");
            goto FAILURE;
        }

        goto RE_REGISTER;
    }

    /// Call the handler

    if (chan->handler) {
        void *reply_buf = NULL;
        size_t reply_size = 0;
        struct capref reply_cap = NULL_CAP;
        bool free_out_payload = true;
        err = chan->handler(chan->arg, recv_identifier, recv_buf, recv_size, recv_cap,
                            &reply_buf, &reply_size, &reply_cap, &free_out_payload, &re_register);

        if (reply_size != -1) {  // -1 means no reply
            if (err_is_ok(err)) {
                err = rpc_lmp_ack(lc, reply_cap, reply_buf, reply_size);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "%s: aos_chan_ack failed\n", __func__);
                }
            } else {
                err = rpc_lmp_nack(lc, err);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "%s: aos_chan_nack failed\n", __func__);
                }
            }
        }

        /* Clean up, regardless of err is ok or fail */
        if (free_out_payload) {
            free(reply_buf);
        }
    }

    /// Deserialization cleanup

    err = rpc_lmp_cleanup(&helper);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "%s: failed to clean up\n", __func__);
    }

FAILURE:
    // Do nothing for now
RE_REGISTER:
    if (re_register) {
        err = lmp_chan_register_recv(lc, get_default_waitset(),
                                     MKCLOSURE(rpc_lmp_generic_handler, arg));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "%s: error re-registering handler\n", __func__);
            /* Only LIB_ERR_CHAN_ALREADY_REGISTERED is possible, safe to discard it */
        }
    }
}

errval_t rpc_lmp_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                            aos_chan_handler_t handler, void *arg)
{
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    chan->handler = handler;
    chan->arg = arg;

    errval_t err = lmp_chan_alloc_recv_slot(&chan->lc);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    return lmp_chan_register_recv(&chan->lc, ws, MKCLOSURE(rpc_lmp_generic_handler, chan));
}