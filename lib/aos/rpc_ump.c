//
// Created by Zikai Liu on 5/29/22.
//

#include <rpc_priv.h>
#include <aos/aos_rpc.h>
#include <aos/paging.h>
#include <aos/domain.h>
#include <string.h>

errval_t rpc_ump_prefix_identifier(const void *buf, size_t size, rpc_identifier_t identifier,
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

static errval_t ump_chan_recv_blocking_dispatch(struct ump_chan *uc, void **payload, size_t *size) {
    errval_t err;
    while (true) {
        err = ump_chan_recv(uc, payload, size);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_RING_NO_MSG) {
                
                err = event_dispatch_non_block(get_default_waitset());
                if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
                    DEBUG_ERR(err, "in event_dispatch");
                    return err;
                }
                
            } else {
                return err_push(err, LIB_ERR_LMP_CHAN_RECV);
            }
        } else {
            return SYS_ERR_OK;
        }
    }
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
    THREAD_MUTEX_ENTER_OR_DISPATCH(&get_init_rpc()->chan.mutex)
    {
        // Step 1: wait for ACK from UMP channel
        err = ump_chan_recv_blocking_dispatch(uc, (void **)&recv_payload, &recv_size);
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
            err = rpc_lmp_call(&get_init_rpc()->chan, RPC_TRANSFER_CAP, call_cap, &uc->pid,
                               sizeof(uc->pid), NULL, NULL, NULL, true);
        } while (lmp_err_is_transient(err));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ump_send_cap: cap transfer step 3 fail\n");
            THREAD_MUTEX_BREAK;
        }
    }
    THREAD_MUTEX_EXIT(&get_init_rpc()->chan.mutex)

    return err;
}

errval_t rpc_ump_recv_cap(struct ump_chan *uc, struct capref *recv_cap)
{
    errval_t err;

    // Prepare the refill slot, do so outside the mutex since it may trigger recursive rpc
    struct capref refill_slot = NULL_CAP;
    err = slot_alloc(&refill_slot);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    // Grab init rpc for capability transfer
    THREAD_MUTEX_ENTER_OR_DISPATCH(&get_init_rpc()->chan.mutex)
    {
        // Step 1: send RPC_ACK_CAP_CHANNEL in UMP channel
        rpc_identifier_t ack = RPC_ACK_CAP_CHANNEL;
        err = ump_chan_send(uc, &ack, sizeof(ack));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_ump_recv_cap: cap transfer step 1 fail\n");
            THREAD_MUTEX_BREAK;
        }

        // Step 2: receive the cap on init channel
        // Work on raw LMP channel to bypass mutex
        struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
        err = lmp_try_recv(&get_init_rpc()->chan.lc, &recv_msg, recv_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_ump_recv_cap: cap transfer step 2 fail\n");
            THREAD_MUTEX_BREAK;
        }

        // Refill the slot with refill_slot, without calling init RPC
        if (!capref_is_null(*recv_cap)) {
            lmp_chan_set_recv_slot(&get_init_rpc()->chan.lc, refill_slot);
        } else {
            err = slot_free(refill_slot);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "rpc_ump_recv_cap: refill_slot fail\n");
            }
        }

        // Step 3: decode the message
        rpc_identifier_t recv_type;
        uint8_t *recv_buf;
        size_t recv_size;
        struct lmp_helper recv_helper;

        err = rpc_lmp_deserialize(&recv_msg, recv_cap, &recv_type, &recv_buf, &recv_size,
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
            DEBUG_ERR(err, "rpc_ump_recv_cap: cap transfer step 3 fail\n");
        } else {
            DEBUG_PRINTF("rpc_ump_recv_cap: unknown identifier %u in step 3\n", recv_type);
            err = LIB_ERR_UMP_CHAN_RECV_CAP_UNKNOWN;
        }

        errval_t err2 = rpc_lmp_cleanup(&recv_helper);
        if (err_is_fail(err2)) {
            DEBUG_ERR(err2, "rpc_ump_recv_cap: failed to clean up\n");
        }
    }
    THREAD_MUTEX_EXIT(&get_init_rpc()->chan.mutex)

    return err;
}

errval_t rpc_ump_send(struct ump_chan *uc, rpc_identifier_t identifier, struct capref cap,
                      const void *buf, size_t size)
{
    errval_t err;

    if (!capref_is_null(cap)) {
        identifier |= RPC_SPECIAL_CAP_TRANSFER_FLAG;
    }

    void *send_payload = NULL;
    err = rpc_ump_prefix_identifier(buf, size, identifier, &send_payload);
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

errval_t rpc_ump_ack(struct ump_chan *uc, struct capref cap, const void *buf, size_t size)
{
    return rpc_ump_send(uc, RPC_ACK, cap, buf, size);
}

errval_t rpc_ump_nack(struct ump_chan *uc, errval_t err)
{
    return rpc_ump_send(uc, RPC_ERR, NULL_CAP, &err, sizeof(errval_t));
}

errval_t rpc_ump_call(struct aos_chan *chan, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size)
{
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->uc;

    errval_t err;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;
    struct capref recv_cap = NULL_CAP;

    THREAD_MUTEX_ENTER_OR_DISPATCH(&chan->mutex)
    {
        // Make the call and transfer cap if needed
        err = rpc_ump_send(uc, identifier, call_cap, call_buf, call_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_ump_call: failed to send\n");
            THREAD_MUTEX_BREAK;
        }

        // Receive acknowledgement and/or return message
        err = ump_chan_recv_blocking_dispatch(uc, (void **)&recv_payload, &recv_size);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV);
            DEBUG_ERR(err, "rpc_ump_call: failed to recv\n");
            THREAD_MUTEX_BREAK;
        }

        // Receive cap if needed
        assert(recv_size >= sizeof(rpc_identifier_t));
        if (CAST_DEREF(rpc_identifier_t, recv_payload, 0) & RPC_SPECIAL_CAP_TRANSFER_FLAG) {
            err = rpc_ump_recv_cap(uc, &recv_cap);
            if (err_is_fail(err)) {
                err = err_push(err, LIB_ERR_UMP_CHAN_RECV_CAP);
                DEBUG_ERR(err, "rpc_ump_call: rpc_ump_recv_cap failed\n");
                THREAD_MUTEX_BREAK;
            }

            // Clear the flag
            CAST_DEREF(rpc_identifier_t, recv_payload, 0) ^= RPC_SPECIAL_CAP_TRANSFER_FLAG;
        }
    }
    THREAD_MUTEX_EXIT(&chan->mutex)
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

static void rpc_ump_generic_handler(void *arg)
{
    bool re_register = true;

    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->uc;

    errval_t err;

    uint8_t *recv_raw_buf = NULL;
    size_t recv_raw_size = 0;

    err = ump_chan_recv(uc, (void **)&recv_raw_buf, &recv_raw_size);
    if (err == LIB_ERR_RING_NO_MSG) {
        goto RE_REGISTER;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "%s: ring_consumer_recv failed\n", __func__);
        goto RE_REGISTER;
    }

    rpc_identifier_t recv_identifier = *((rpc_identifier_t *)recv_raw_buf);
    uint8_t *recv_buf = recv_raw_buf + sizeof(rpc_identifier_t);
    size_t recv_size = recv_raw_size - sizeof(rpc_identifier_t);

    struct capref recv_cap = NULL_CAP;
    if (recv_identifier & RPC_SPECIAL_CAP_TRANSFER_FLAG) {
        err = rpc_ump_recv_cap(uc, &recv_cap);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV_CAP);
            DEBUG_ERR(err, "%s: rpc_ump_recv_cap failed\n", __func__);
            goto CLEANUP;
        }

        /* Clear the flag */
        recv_identifier ^= RPC_SPECIAL_CAP_TRANSFER_FLAG;
    }

    /* Call the handler */
    if (chan->handler) {
        void *reply_buf = NULL;
        size_t reply_size = 0;
        struct capref reply_cap = NULL_CAP;
        bool free_out_payload = true;
        err = chan->handler(chan->arg, recv_identifier, recv_buf, recv_size, recv_cap,
                            &reply_buf, &reply_size, &reply_cap, &free_out_payload, &re_register);

        if (err_is_fail(err)) {
            err = rpc_ump_nack(uc, err);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "%s: aos_chan_nack failed\n", __func__);
            }
        } else {
            err = rpc_ump_ack(uc, reply_cap, reply_buf, reply_size);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "%s: aos_chan_ack failed\n", __func__);
            }
        }
        if (free_out_payload) {
            free(reply_buf);
        }
    }

CLEANUP:
    free(recv_raw_buf);
RE_REGISTER:
    if (re_register) {
        err = ump_chan_register_recv(uc, get_default_waitset(),
                                     MKCLOSURE(rpc_ump_generic_handler, arg));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "%s: error re-registering handler", __func__);
            /* Only LIB_ERR_CHAN_ALREADY_REGISTERED is possible, safe to discard it */
        }
    }
}


errval_t rpc_ump_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                                    aos_chan_handler_t handler, void *arg)
{
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    chan->handler = handler;
    chan->arg = arg;
    return ump_chan_register_recv(&chan->uc, ws, MKCLOSURE(rpc_ump_generic_handler, chan));
}
