/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/capabilities.h>

// terminal state for multiplexing terminal resource
void* terminal_state = NULL;

typedef uint8_t lmp_single_msg_size_t;

#define LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE                                                  \
    (LMP_MSG_LENGTH * sizeof(uintptr_t) - sizeof(lmp_single_msg_size_t)                  \
     - sizeof(rpc_identifier_t))

STATIC_ASSERT(LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE
                  <= (1 << (sizeof(lmp_single_msg_size_t) * 8)),
              "lmp_single_msg_size_t too small");

errval_t lmp_serialize(rpc_identifier_t identifier, struct capref cap, const void *buf,
                       size_t size, uintptr_t ret_payload[LMP_MSG_LENGTH],
                       struct capref *ret_cap, struct lmp_helper *helper)
{
    errval_t err;
    helper->payload_frame = NULL_CAP;
    helper->mapped_frame = NULL;

    if (buf == NULL && size != 0) {
        return ERR_INVALID_ARGS;
    }

    if (size <= LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE) {
        // Buffer fits in the remaining space
        CAST_DEREF(lmp_single_msg_size_t, ret_payload, 0) = (lmp_single_msg_size_t)size;
        CAST_DEREF(rpc_identifier_t, ret_payload, sizeof(lmp_single_msg_size_t))
            = identifier;
        memcpy(
            OFFSET(ret_payload, sizeof(lmp_single_msg_size_t) + sizeof(rpc_identifier_t)),
            buf, size);
        *ret_cap = cap;

    } else {
        // Buffer doesn't fit, make and map frame cap
#if 0
        DEBUG_PRINTF("lmp_serialize: alloc frame\n");
#endif

        if (!capref_is_null(cap)) {
            return LIB_ERR_RPC_LARGE_MSG_WITH_CAP;
        }

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

errval_t lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref *recv_cap,
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
        assert(!capref_is_null(*recv_cap));

#if 0
        DEBUG_PRINTF("lmp_deserialize: trying to map received frame in local space\n");
#endif

        struct frame_identity frame_id;
        err = frame_identify(*recv_cap, &frame_id);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_FRAME_IDENTIFY);
        }

        err = paging_map_frame(get_current_paging_state(), (void **)&frame_payload,
                               frame_id.bytes, *recv_cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_MAP);
        }

        size = CAST_DEREF(size_t, frame_payload, 0);
        type = CAST_DEREF(rpc_identifier_t, frame_payload, sizeof(size_t));  // replace
        buf = OFFSET(frame_payload, sizeof(size_t) + sizeof(rpc_identifier_t));

        helper->payload_frame = *recv_cap;
        helper->mapped_frame = frame_payload;

        *recv_cap = NULL_CAP;  // no cap is actually received
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

errval_t lmp_cleanup(struct lmp_helper *helper)
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

errval_t ump_prefix_identifier(const void *buf, size_t size, rpc_identifier_t identifier,
                               void **ret)
{
    uint8_t *new_buf = malloc(sizeof(rpc_identifier_t) + size);
    if (new_buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    CAST_DEREF(rpc_identifier_t, new_buf, 0) = identifier;
    if (size != 0) {
        memcpy(OFFSET(new_buf, sizeof(rpc_identifier_t)), buf, size);
    }
    *ret = new_buf;
    return SYS_ERR_OK;
}

errval_t lmp_try_send(struct lmp_chan *lc, uintptr_t *send_words, struct capref send_cap,
                      bool no_blocking)
{
    errval_t err;
    while (true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, send_cap, send_words[0],
                             send_words[1], send_words[2], send_words[3]);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                if (no_blocking) {
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

static errval_t rpc_lmp_send(struct lmp_chan *lc, rpc_identifier_t identifier,
                             struct capref cap, const void *buf, size_t size,
                             bool no_blocking)
{
    errval_t err;
    uintptr_t send_words[LMP_MSG_LENGTH];
    struct capref send_cap;
    struct lmp_helper send_helper;

    err = lmp_serialize(identifier, cap, buf, size, send_words, &send_cap, &send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    // Send
    err = lmp_try_send(lc, send_words, send_cap, no_blocking);
    if (err_is_fail(err)) {
        return err;  // expose transient error directly
    }

    // Clean up
    err = lmp_cleanup(&send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CLEANUP);
    }

    return SYS_ERR_OK;
}

static errval_t rpc_lmp_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                             struct capref call_cap, const void *call_buf,
                             size_t call_size, struct capref *ret_cap, void **ret_buf,
                             size_t *ret_size, bool no_lock)
{
    assert(rpc->chan.type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &rpc->chan.lc;

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
    err = lmp_serialize(identifier, call_cap, call_buf, call_size, send_words, &send_cap,
                        &send_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap = NULL_CAP;

    THREAD_MUTEX_ENTER_IF(&rpc->mutex, !no_lock)
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
    THREAD_MUTEX_EXIT_IF(&rpc->mutex, !no_lock)
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

    err = lmp_deserialize(&recv_msg, &recv_cap, &recv_type, &recv_buf, &recv_size,
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
    errval_t err2 = lmp_cleanup(&send_helper);
    if (err_is_fail(err2)) {
        DEBUG_ERR(err2, "rpc_lmp_call: failed to clean up\n");
    }
    err2 = lmp_cleanup(&recv_helper);
    if (err_is_fail(err2)) {
        DEBUG_ERR(err2, "rpc_lmp_call: failed to clean up\n");
    }

    return err;
}

static errval_t ump_send_cap(struct ump_chan *uc, struct capref call_cap)
{
    if (uc->pid == 0) {
        return LIB_ERR_UMP_CHAN_SEND_CAP_NO_PID;
    }

    errval_t err;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;

    // Grab init rpc for capability transfer
    THREAD_MUTEX_ENTER(&get_init_rpc()->mutex)
    {
        // Step 1: wait for ACK from UMP channel
        err = ump_chan_recv_blocking(uc, (void **)&recv_payload, &recv_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ump_send_cap: cap transfer step 1 fail\n");
            THREAD_MUTEX_BREAK;
        }

        // Step 2: decode the reply and make sure it's RPC_ACK_CAP_CHANNEL
        assert(recv_size >= sizeof(rpc_identifier_t));
        rpc_identifier_t recv_identifier = CAST_DEREF(rpc_identifier_t, recv_payload, 0);
        if (recv_identifier == RPC_ACK_CAP_CHANNEL) {
            // pass
            assert(recv_size == sizeof(rpc_identifier_t));
        } else if (recv_identifier == RPC_ERR) {
            assert(recv_size == sizeof(rpc_identifier_t) + sizeof(errval_t));
            err = CAST_DEREF(errval_t, recv_payload, sizeof(rpc_identifier_t));
            DEBUG_ERR(err, "ump_send_cap: cap transfer step 2 fail\n");
            THREAD_MUTEX_BREAK;
        } else {
            DEBUG_PRINTF("ump_send_cap: unknown identifier %u (size = %lu) in step 2\n",
                         recv_identifier, recv_size);
            err = LIB_ERR_UMP_CHAN_SEND_CAP_NO_ACK;
            THREAD_MUTEX_BREAK;
        }
        free(recv_payload);

        // Step 3: send the cap through init
        // There must be no way to trigger recursive init RPC call inside
        do {
            err = rpc_lmp_call(get_init_rpc(), RPC_TRANSFER_CAP, call_cap, &uc->pid,
                               sizeof(uc->pid), NULL, NULL, NULL, true);
        } while (lmp_err_is_transient(err));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ump_send_cap: cap transfer step 3 fail\n");
            THREAD_MUTEX_BREAK;
        }
    }
    THREAD_MUTEX_EXIT(&get_init_rpc()->mutex)

    return err;
}

errval_t ump_recv_cap(struct ump_chan *uc, struct capref *recv_cap)
{
    errval_t err;

    // Prepare the refill slot, do so outside the mutex since it may trigger recursive rpc
    struct capref refill_slot = NULL_CAP;
    err = slot_alloc(&refill_slot);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    // Grab init rpc for capability transfer
    THREAD_MUTEX_ENTER(&get_init_rpc()->mutex)
    {
        // Step 1: send RPC_ACK_CAP_CHANNEL in UMP channel
        rpc_identifier_t ack = RPC_ACK_CAP_CHANNEL;
        err = ump_chan_send(uc, &ack, sizeof(ack));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ump_recv_cap: cap transfer step 1 fail\n");
            THREAD_MUTEX_BREAK;
        }

        // Step 2: receive the cap on init channel
        // Work on raw LMP channel to bypass mutex
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
        err = lmp_try_recv(&get_init_rpc()->chan.lc, &recv_msg, recv_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ump_recv_cap: cap transfer step 2 fail\n");
            THREAD_MUTEX_BREAK;
        }

        // Refill the slot with refill_slot, without calling init RPC
        if (!capref_is_null(*recv_cap)) {
            lmp_chan_set_recv_slot(&get_init_rpc()->chan.lc, refill_slot);
        } else {
            err = slot_free(refill_slot);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "ump_recv_cap: refill_slot fail\n");
            }
        }

        // Step 3: decode the message
        rpc_identifier_t recv_type;
        uint8_t *recv_buf;
        size_t recv_size;
        struct lmp_helper recv_helper;

        err = lmp_deserialize(&recv_msg, recv_cap, &recv_type, &recv_buf, &recv_size,
                              &recv_helper);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_LMP_DESERIALIZE);
            THREAD_MUTEX_BREAK;
        }
        if (recv_type == RPC_PUT_CAP) {
            // pass
            assert(recv_size == 0);
            assert(!capref_is_null(*recv_cap));
        } else if (recv_type == RPC_ERR) {
            assert(recv_size == sizeof(errval_t));
            err = CAST_DEREF(errval_t, recv_buf, 0);
            DEBUG_ERR(err, "ump_recv_cap: cap transfer step 3 fail\n");
        } else {
            DEBUG_PRINTF("ump_recv_cap: unknown identifier %u in step 3\n", recv_type);
            err = LIB_ERR_UMP_CHAN_RECV_CAP_UNKNOWN;
        }

        errval_t err2 = lmp_cleanup(&recv_helper);
        if (err_is_fail(err2)) {
            DEBUG_ERR(err2, "ump_recv_cap: failed to clean up\n");
        }
    }
    THREAD_MUTEX_EXIT(&get_init_rpc()->mutex)

    return err;
}

static errval_t rpc_ump_send(struct ump_chan *uc, rpc_identifier_t identifier,
                             struct capref cap, const void *buf, size_t size)
{
    errval_t err;

    if (!capref_is_null(cap)) {
        identifier |= RPC_SPECIAL_CAP_TRANSFER_FLAG;
    }

    void *send_payload = NULL;
    err = ump_prefix_identifier(buf, size, identifier, &send_payload);
    if (err_is_fail(err)) {
        return err;
    }

    err = ump_chan_send(uc, send_payload, size + sizeof(rpc_identifier_t));
    if (err_is_fail(err)) {
        free(send_payload);
        return err_push(err, LIB_ERR_UMP_CHAN_SEND);
    }

    if (!capref_is_null(cap)) {
        err = ump_send_cap(uc, cap);
        if (err_is_fail(err)) {
            free(send_payload);
            return err_push(err, LIB_ERR_UMP_CHAN_SEND_CAP);
        }
    }

    free(send_payload);
    return SYS_ERR_OK;
}

static errval_t rpc_ump_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                             struct capref call_cap, const void *call_buf,
                             size_t call_size, struct capref *ret_cap, void **ret_buf,
                             size_t *ret_size)
{
    assert(rpc->chan.type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &rpc->chan.uc;

    errval_t err;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;
    struct capref recv_cap = NULL_CAP;

    THREAD_MUTEX_ENTER(&rpc->mutex)
    {
        // Make the call and transfer cap if needed
        err = rpc_ump_send(uc, identifier, call_cap, call_buf, call_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_ump_call: failed to send\n");
            THREAD_MUTEX_BREAK;
        }

        // Receive acknowledgement and/or return message
        err = ump_chan_recv_blocking(uc, (void **)&recv_payload, &recv_size);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV);
            DEBUG_ERR(err, "rpc_ump_call: failed to recv\n");
            THREAD_MUTEX_BREAK;
        }

        // Receive cap if needed
        assert(recv_size >= sizeof(rpc_identifier_t));
        if (CAST_DEREF(rpc_identifier_t, recv_payload, 0) & RPC_SPECIAL_CAP_TRANSFER_FLAG) {
            err = ump_recv_cap(uc, &recv_cap);
            if (err_is_fail(err)) {
                err = err_push(err, LIB_ERR_UMP_CHAN_RECV_CAP);
                DEBUG_ERR(err, "rpc_ump_call: ump_recv_cap failed\n");
                THREAD_MUTEX_BREAK;
            }

            // Clear the flag
            CAST_DEREF(rpc_identifier_t, recv_payload, 0) ^= RPC_SPECIAL_CAP_TRANSFER_FLAG;
        }
    }
    THREAD_MUTEX_EXIT(&rpc->mutex)
    // Handle error happened in the critical section
    if (err_is_fail(err)) {
        goto RET;
    }

    if (CAST_DEREF(rpc_identifier_t, recv_payload, 0) == RPC_ACK) {
        if (ret_buf != NULL) {
            // XXX: it is annoying to malloc a new buf and make the copy just to remove
            //      the identifier. Consider moving it into ring buffer.
            *ret_size = recv_size - sizeof(rpc_identifier_t);
            *ret_buf = malloc(*ret_size);
            if (*ret_buf == NULL) {
                err = LIB_ERR_MALLOC_FAIL;
                goto RET;
            }
            memcpy(*ret_buf, recv_payload + sizeof(rpc_identifier_t), *ret_size);
        }

        if (!capref_is_null(recv_cap)) {
            if (ret_cap == NULL) {
                DEBUG_PRINTF("rpc_ump_call: received a cap but is given up!\n");
            } else {
                *ret_cap = recv_cap;
            }
        }
        err = SYS_ERR_OK;
        goto RET;
    } else {
        assert(recv_size == sizeof(rpc_identifier_t) + sizeof(errval_t));
        err = *((errval_t *)(recv_payload + sizeof(rpc_identifier_t)));
        goto RET;
    }

RET:
    free(recv_payload);
    return err;
}

errval_t aos_rpc_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size)
{
    switch (rpc->chan.type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_call(rpc, identifier, call_cap, call_buf, call_size, ret_cap,
                            ret_buf, ret_size, false);
    case AOS_CHAN_TYPE_UMP:
        return rpc_ump_call(rpc, identifier, call_cap, call_buf, call_size, ret_cap,
                            ret_buf, ret_size);
    default:
        assert(!"aos_chan_nack: unknown rpc->chan.type");
    }
}

errval_t aos_chan_send(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref cap, const void *buf, size_t size, bool no_blocking)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_send(&chan->lc, identifier, cap, buf, size, no_blocking);
    case AOS_CHAN_TYPE_UMP:
        return rpc_ump_send(&chan->uc, identifier, cap, buf, size);
    default:
        assert(!"aos_chan_nack: unknown chan->type");
    }
}

errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, const void *buf,
                      size_t size)
{
    return aos_chan_send(chan, RPC_ACK, cap, buf, size, false);
}

errval_t lmp_put_cap(struct lmp_chan *lc, struct capref cap)
{
    assert(!capref_is_null(cap));
    return rpc_lmp_send(lc, RPC_PUT_CAP, cap, NULL, 0, false);
}

errval_t aos_chan_nack(struct aos_chan *chan, errval_t err)
{
    return aos_chan_send(chan, RPC_ERR, NULL_CAP, &err, sizeof(errval_t), false);
}


errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err = aos_rpc_call(rpc, RPC_NUM, NULL_CAP, &num, sizeof(num), NULL, NULL,
                                NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err = aos_rpc_call(rpc, RPC_STR, NULL_CAP, (void *)string,
                                strlen(string) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_stress_test(struct aos_rpc *rpc, uint8_t *val, size_t len)
{
    errval_t err = aos_rpc_call(rpc, RPC_STRESS_TEST, NULL_CAP, (void *)val, len, NULL,
                                NULL, NULL);
    if (err_is_fail(err))
        return err;

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: start\n");
    struct aos_rpc_msg_ram msg = { .size = bytes, .alignment = alignment };
    errval_t err = aos_rpc_call(rpc, RPC_RAM_REQUEST, NULL_CAP, &msg, sizeof(msg),
                                ret_cap, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive RAM\n");
        return err;
    }

    if (ret_bytes != NULL) {
        // No better way as of now (mm does not return any size)
        struct capability c;
        err = cap_direct_identify(*ret_cap, &c);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to get the frame info\n");
            return err_push(err, LIB_ERR_CAP_IDENTIFY);
        }
        assert(c.type == ObjType_RAM);
        assert(c.u.ram.bytes >= bytes);
        *ret_bytes = c.u.ram.bytes;
    }
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: done\n");
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;
    char *ret_char = NULL;
    size_t ret_size = 0;
    err = aos_rpc_call(rpc, RPC_TERMINAL_GETCHAR, NULL_CAP, &terminal_state, sizeof(void*), NULL,
                       (void **)&ret_char, &ret_size);
    if (err_is_ok(err)) {
        assert(ret_size >= sizeof(char));
        *retc = *ret_char;
    }
	
    free(ret_char);
    return err;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // we don't care about return values or capabilities, just send this single char
    // (again, do better)
    // sys_print("aos_rpc_serial_putchar called!\n", 32);
    errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_PUTCHAR, NULL_CAP, &c, sizeof(char),
                                NULL, NULL, NULL);
	

    return err;
}

errval_t aos_rpc_serial_puts(struct aos_rpc *rpc, const char *buf, size_t len, size_t *retlen)
{
	size_t *rbuf = NULL;
	size_t rlen = 0;
	char* tmp_buf = alloca(len+1);
	memcpy(tmp_buf, buf, len);
	tmp_buf[len] = 0;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_PUTS, NULL_CAP, tmp_buf, len+1, NULL, (void**)&rbuf, &rlen);
	
	assert(rlen >= sizeof(size_t));
	*retlen = *rbuf;
	free(rbuf);
		
	return err;
}

errval_t aos_rpc_serial_gets(struct aos_rpc *rpc, char *buf, size_t len, size_t *retlen)
{
	char* tmp_buf;
	char* inbuf[sizeof(void*) + sizeof(size_t)];
	*(void**)inbuf = terminal_state;
	*(size_t*)((void**)inbuf + 1) = len;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_GETS, NULL_CAP, &inbuf, sizeof(void*) + sizeof(size_t), NULL, (void**)&tmp_buf, retlen);
	memcpy(buf, tmp_buf, MIN(len, *retlen));
	
	return err;
}

errval_t aos_rpc_serial_aquire(struct aos_rpc *rpc, uint8_t use_stdin)
{
	return aos_rpc_serial_aquire_new_state(rpc, &terminal_state, use_stdin);
}

errval_t aos_rpc_serial_aquire_new_state(struct aos_rpc *rpc, void** st, uint8_t attach_stdin)
{
	size_t rlen = 0;
	void* st_ret;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_AQUIRE, NULL_CAP, &attach_stdin, sizeof(uint8_t), NULL, &st_ret, &rlen);
	
	*st = *(void**)st_ret;
	
	return err;
}

errval_t aos_rpc_serial_release(struct aos_rpc *rpc)
{
	errval_t err = aos_rpc_serial_release_terminal_state(rpc, terminal_state);
	terminal_state = NULL;
	return err;
}

errval_t aos_rpc_serial_release_terminal_state(struct aos_rpc *rpc, void* st)
{
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_RELEASE, NULL_CAP, &st, sizeof(void*), NULL, NULL, NULL);
	
	return err;
}

errval_t aos_rpc_serial_has_stdin(struct aos_rpc *rpc, bool *can_access_stdin)
{
	bool* can_access;
	size_t rlen;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_HAS_STDIN, NULL_CAP, &terminal_state, sizeof(void*), NULL, (void**)&can_access, &rlen);
	
	if (rlen >= sizeof(bool)) *can_access_stdin = *can_access;
	
	free(can_access);
	
	return err;
}


errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core, domainid_t *newpid)
{
    return aos_rpc_process_spawn_with_terminal_state(rpc, cmdline, NULL, core, newpid);
}

errval_t aos_rpc_process_spawn_with_terminal_state(struct aos_rpc *rpc, char *cmdline, void* st, coreid_t core, domainid_t *newpid)
{
	size_t call_msg_size = sizeof(struct rpc_process_spawn_call_msg) + strlen(cmdline) + 1;
    struct rpc_process_spawn_call_msg *call_msg = calloc(call_msg_size, 1);
    call_msg->core = core;
	call_msg->terminal_state = st;
    strcpy(call_msg->cmdline, cmdline);

    domainid_t *return_pid = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_SPAWN_WITH_STDIN, NULL_CAP, call_msg, call_msg_size,
                                NULL, (void **)&return_pid, NULL);
    if (err_is_ok(err)) {
        *newpid = *return_pid;
    }  // on failure, fall through

    free(call_msg);
    free(return_pid);
    return err;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    char *return_msg = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_NAME, NULL_CAP, &pid,
                                sizeof(domainid_t), NULL, (void **)&return_msg, NULL);
    if (err_is_fail(err)) {
        free(return_msg);
        return err;
    }
    *name = return_msg;
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    struct rpc_process_get_all_pids_return_msg *return_msg = NULL;
    size_t return_size = 0;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_ALL_PIDS, NULL_CAP, NULL, 0, NULL,
                                (void **)&return_msg, &return_size);
    if (err_is_ok(err)) {
        *pid_count = return_msg->count;
        *pids = malloc(return_msg->count * sizeof(domainid_t));
        if (*pids == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(*pids, return_msg->pids, return_msg->count * sizeof(domainid_t));
    }  // on failure, fall through

    free(return_msg);
    return err;
}


errval_t aos_rpc_process_kill_pid(struct aos_rpc *rpc, domainid_t pid)
{
	return aos_rpc_call(rpc, RPC_PROCESS_KILL_PID, NULL_CAP, &pid, sizeof(domainid_t), NULL, NULL, NULL);
}

errval_t aos_rpc_fopen(struct aos_rpc *rpc, const char *path, handle_t *handle) 
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FOPEN, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg);
        free(return_msg);
    }

    free(return_msg);
    return err;
}

errval_t aos_rpc_fclose(struct aos_rpc *rpc, handle_t handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FCLOSE, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_fcreate(struct aos_rpc *rpc, const char *path, handle_t *handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FCREATE, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg + sizeof(errval_t));
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_frm(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FRM, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_fread(struct aos_rpc *rpc, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(size_t);
    void *send_msg = malloc(sizeof(lvaddr_t) + sizeof(size_t));
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &bytes, sizeof(size_t));

    errval_t err = aos_rpc_call(rpc, RPC_FREAD, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);
    free(send_msg);
    if(err_is_ok(err)) {
        *ret_bytes = *(size_t *)(return_msg);
        memcpy(buffer, return_msg + sizeof(size_t), *ret_bytes);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fwrite(struct aos_rpc *rpc, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(size_t) + bytes;
    void *send_msg = malloc(send_size);
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &bytes, sizeof(size_t));
    memcpy(send_msg + sizeof(lvaddr_t) + bytes, buffer, bytes);

    errval_t err = aos_rpc_call(rpc, RPC_FWRITE, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);
    free(send_msg);
    if(err_is_ok(err)) {
        *ret_bytes = *(size_t *)(return_msg + sizeof(errval_t));
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fseek(struct aos_rpc *rpc, handle_t handle, enum fs_seekpos whence, off_t offset)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(enum fs_seekpos) + sizeof(off_t);
    void *send_msg = malloc(send_size);
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &whence, sizeof(enum fs_seekpos));
    memcpy(send_msg + sizeof(lvaddr_t) + sizeof(enum fs_seekpos), &offset, sizeof(off_t));

    errval_t err = aos_rpc_call(rpc, RPC_FSEEK, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);
    free(send_msg);

    return err;
}

errval_t aos_rpc_ftell(struct aos_rpc *rpc, handle_t handle, size_t *ret_offset)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FTELL, NULL_CAP, &handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *ret_offset = *(size_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_opendir(struct aos_rpc *rpc, const char *path, handle_t *handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_OPENDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_mkdir(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_MKDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_rmdir(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_RMDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_closedir(struct aos_rpc *rpc, handle_t handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_CLOSEDIR, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_readdir_next(struct aos_rpc *rpc, handle_t handle, char **name)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_READDIR, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        size_t length = *(size_t *)(return_msg);
        *name = malloc(length + 1);
        memcpy(*name, return_msg + sizeof(size_t), length);
        (*name)[length] = '\0';
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fstat(struct aos_rpc *rpc, handle_t handle, struct fs_fileinfo *info)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FSTAT, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *info = *(struct fs_fileinfo *)(return_msg);
        free(return_msg);
    }

    return err;
}


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    // debug_printf("aos_rpc_get_serial_channel NYI\n");
    return aos_rpc_get_init_channel();  // XXX: For now return the init channel, since the
                                        // current serial driver is handled in init
}

void aos_rpc_init(struct aos_rpc *rpc)
{
    memset(rpc, 0, sizeof(*rpc));
    assert(rpc->chan.type == AOS_CHAN_TYPE_UNKNOWN);
    thread_mutex_init(&rpc->mutex);
}

void aos_rpc_destroy(struct aos_rpc *rpc)
{
    aos_chan_destroy(&rpc->chan);
}

void aos_chan_destroy(struct aos_chan *chan)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        lmp_chan_destroy(&chan->lc);
        break;
    case AOS_CHAN_TYPE_UMP:
        ump_chan_destroy(&chan->uc);
        break;
    default:
        break;
    }
}