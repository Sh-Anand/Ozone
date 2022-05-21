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

#define UMP_RECV_CAP_IF_ANY(uc)                                                          \
    struct capref recv_cap = NULL_CAP;                                                   \
    if (recv_type & RPC_SPECIAL_CAP_TRANSFER_FLAG) {                                     \
        err = ump_recv_cap(uc, &recv_cap);                                               \
        if (err_is_fail(err)) {                                                          \
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV_CAP);                              \
            DEBUG_ERR(err, "%s: ump_recv_cap failed\n", __func__);                       \
            goto FAILURE;                                                                \
        }                                                                                \
                                                                                         \
        /* Clear the flag */                                                             \
        recv_type ^= RPC_SPECIAL_CAP_TRANSFER_FLAG;                                      \
    }

#define UMP_RECV_NO_CAP                                                                  \
    struct capref recv_cap = NULL_CAP;                                                   \
    if (recv_type & RPC_SPECIAL_CAP_TRANSFER_FLAG) {                                     \
        DEBUG_PRINTF("%s: why receive a cap? recv_type = %u\n", __func__, recv_type);    \
        goto FAILURE;                                                                    \
    }

#define UMP_ASSERT_DISPATCHER(rpc_handlers, count)                                       \
    if (recv_type >= count || rpc_handlers[recv_type] == NULL) {                         \
        DEBUG_PRINTF("%s: invalid URPC msg %u\n", __func__, recv_type);                  \
        goto FAILURE;                                                                    \
    }

#define UMP_DISPATCH_AND_REPLY_MAY_FAIL(chan, handler, st)                               \
    void *reply_payload = NULL;                                                          \
    size_t reply_size = 0;                                                               \
    struct capref reply_cap = NULL_CAP;                                                  \
    err = handler(st, recv_buf, recv_size, &reply_payload, &reply_size, recv_cap,        \
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

#define UMP_DISPATCH_AND_REPLY_NO_FAIL(chan, handler, st)                                \
    void *reply_payload = NULL;                                                          \
    size_t reply_size = 0;                                                               \
    struct capref reply_cap = NULL_CAP;                                                  \
    handler(st, recv_buf, recv_size, &reply_payload, &reply_size, recv_cap, &reply_cap); \
                                                                                         \
                                                                                         \
    err = aos_chan_ack(chan, reply_cap, reply_payload, reply_size);                      \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: aos_chan_ack failed\n", __func__);                           \
    }                                                                                    \
                                                                                         \
    free(reply_payload);

#define UMP_CLEANUP_AND_RE_REGISTER(uc, func, arg)                                       \
FAILURE:                                                                                 \
    free(recv_raw_buf);                                                                  \
RE_REGISTER:                                                                             \
    err = ump_chan_register_recv(uc, get_default_waitset(), MKCLOSURE(func, arg));       \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: error re-registering handler", __func__);                    \
        /* Only LIB_ERR_CHAN_ALREADY_REGISTERED is possible, safe to discard it */       \
    }

#endif  // AOS_UMP_HANDLER_BUILDER_H
