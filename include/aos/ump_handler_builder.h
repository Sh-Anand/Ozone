//
// Created by Zikai Liu on 5/20/22.
//

#ifndef AOS_UMP_HANDLER_BUILDER_H
#define AOS_UMP_HANDLER_BUILDER_H

#define UMP_RECV_DESERIALIZE(uc)                                                         \
    uint8_t *recv_raw_buf = NULL;                                                        \
    size_t recv_raw_size = 0;                                                            \
                                                                                         \
    err = ump_chan_recv(uc, (void **)&recv_raw_buf, &recv_raw_size);                     \
    if (err == LIB_ERR_RING_NO_MSG) {                                                    \
        goto RE_REGISTER;                                                                \
    }                                                                                    \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: ring_consumer_recv failed\n", __func__);                     \
        goto RE_REGISTER;                                                                \
    }                                                                                    \
                                                                                         \
    rpc_identifier_t recv_type = *((rpc_identifier_t *)recv_raw_buf);                    \
    uint8_t *recv_buf = recv_raw_buf + sizeof(rpc_identifier_t);                         \
    size_t recv_size = recv_raw_size - sizeof(rpc_identifier_t);

#define UMP_RECV_CAP(uc)                                                                 \
    struct capref recv_cap = NULL_CAP;                                                   \
    if (recv_type & RPC_SPECIAL_CAP_TRANSFER_FLAG) {                                     \
        err = ump_recv_cap(uc, &recv_cap);                                               \
        if (err_is_fail(err)) {                                                          \
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV_CAP);                              \
            DEBUG_ERR(err, "%s: ump_recv_cap failed\n", __func__);                       \
            goto FREE_RECV_PAYLOAD;                                                      \
        }                                                                                \
                                                                                         \
        /* Clear the flag */                                                             \
        recv_type ^= RPC_SPECIAL_CAP_TRANSFER_FLAG;                                      \
    }

#define UMP_DISPATCH_MAY_FAIL(chan, handler)                                             \
    void *reply_payload = NULL;                                                          \
    size_t reply_size = 0;                                                               \
    struct capref reply_cap = NULL_CAP;                                                  \
    err = handler(NULL, recv_buf, recv_size, &reply_payload, &reply_size, recv_cap,      \
                  &reply_cap);                                                           \
                                                                                         \
    if (err_is_fail(err)) {                                                              \
        err = aos_chan_nack(chan, err);                                                  \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, "%s: aos_chan_nack failed\n", __func__);                      \
        }                                                                                \
    } else {                                                                             \
        err = aos_chan_ack(chan, reply_cap, reply_payload, reply_size);                  \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, "%s: aos_chan_ack failed\n", __func__);                       \
        }                                                                                \
    }                                                                                    \
    free(reply_payload);

#define UMP_CLEANUP_AND_RE_REGISTER(uc, func, arg)                                       \
FREE_RECV_PAYLOAD:                                                                       \
    free(recv_raw_buf);                                                                  \
RE_REGISTER:                                                                             \
    err = ump_chan_register_recv(uc, get_default_waitset(), MKCLOSURE(func, arg));       \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: error re-registering handler", __func__);                    \
        /* Only LIB_ERR_CHAN_ALREADY_REGISTERED is possible, safe to discard it */       \
    }

#endif  // AOS_UMP_HANDLER_BUILDER_H
