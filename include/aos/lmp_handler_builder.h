//
// Created by Zikai Liu on 5/15/22.
//

#ifndef AOS_LMP_HANDLER_BUILDER_H
#define AOS_LMP_HANDLER_BUILDER_H

#define LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type,          \
                                    recv_buf, recv_size, helper, RE_REGISTER, FAILURE)   \
    struct lmp_recv_msg recv_raw_msg = LMP_RECV_MSG_INIT;                                \
    struct capref recv_cap;                                                              \
                                                                                         \
    /* Try to receive a message */                                                       \
    err = lmp_chan_recv(lc, &recv_raw_msg, &recv_cap);                                   \
    if (err_is_fail(err)) {                                                              \
        if (lmp_err_is_transient(err)) {                                                 \
            goto RE_REGISTER;                                                            \
        }                                                                                \
        DEBUG_ERR(err, "%s: unhandled error from lmp_chan_recv\n", __func__);            \
        goto FAILURE;                                                                    \
    }                                                                                    \
                                                                                         \
    /* Refill the recv_cap slot if the recv slot is used (received a recv_cap) */        \
    if (!capref_is_null(recv_cap)) {                                                     \
        err = lmp_chan_alloc_recv_slot(lc);                                              \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, "%s: fail to alloc new slot\n", __func__);                    \
            goto FAILURE;                                                                \
        }                                                                                \
    }                                                                                    \
    /* Deserialize */                                                                    \
    rpc_identifier_t recv_type;                                                          \
    uint8_t *recv_buf;                                                                   \
    size_t recv_size;                                                                    \
    struct lmp_helper helper;                                                            \
    err = lmp_deserialize(&recv_raw_msg, &recv_cap, &recv_type, &recv_buf, &recv_size,   \
                          &helper);                                                      \
    if (err_is_fail(err)) {                                                              \
        err = err_push(err, LIB_ERR_LMP_SERIALIZE);                                      \
        DEBUG_ERR(err, "%s: fail to deserialize\n", __func__);                           \
        goto FAILURE;                                                                    \
    }

#define LMP_TRY_SETUP_BINDING(err, lc, recv_cap, FAILURE)                                \
    assert(lc->connstate == LMP_BIND_WAIT);                                              \
    /* Check the received endpoint */                                                    \
    if (capref_is_null(recv_cap)) {                                                      \
        DEBUG_PRINTF("%s (binding): no cap received\n", __func__);                       \
        goto FAILURE;                                                                    \
    }                                                                                    \
    struct capability capability;                                                        \
    err = cap_direct_identify(recv_cap, &capability);                                    \
    if (capref_is_null(recv_cap)) {                                                      \
        DEBUG_ERR(err, "%s (binding): cap_direct_identify failed\n", __func__);          \
        goto FAILURE;                                                                    \
    }                                                                                    \
    if (capability.type != ObjType_EndPointLMP) {                                        \
        DEBUG_ERR(err, "%s (binding): recv cap type %u\n", __func__, capability.type);   \
        goto FAILURE;                                                                    \
    }                                                                                    \
    lc->remote_cap = recv_cap;                                                           \
    lc->connstate = LMP_CONNECTED;


#define LMP_DISPATCH_AND_REPLY_MAY_FAIL(err, chan, st, rpc_handler, recv_cap)            \
    {                                                                                    \
        /* Call the handler */                                                           \
        void *reply_payload = NULL;                                                      \
        size_t reply_size = 0;                                                           \
        struct capref reply_cap = NULL_CAP;                                              \
        err = rpc_handler(st, recv_buf, recv_size, &reply_payload, &reply_size,          \
                          recv_cap, &reply_cap);                                         \
        if (err_is_ok(err)) {                                                            \
            err = aos_chan_ack(chan, reply_cap, reply_payload, reply_size);              \
            if (err_is_fail(err)) {                                                      \
                DEBUG_ERR(err, "%s: aos_chan_ack failed\n", __func__);                   \
            }                                                                            \
        } else {                                                                         \
            err = aos_chan_nack(chan, err);                                              \
            if (err_is_fail(err)) {                                                      \
                DEBUG_ERR(err, "%s: aos_chan_nack failed\n", __func__);                  \
            }                                                                            \
        }                                                                                \
                                                                                         \
        /* Clean up, regardless of err is ok or fail */                                  \
        if (reply_payload != NULL) {                                                     \
            free(reply_payload);                                                         \
        }                                                                                \
    }

#define LMP_DISPATCH_AND_REPLY_NO_FAIL(err, chan, st, rpc_handler, recv_cap)             \
    {                                                                                    \
        /* Call the handler */                                                           \
        void *reply_payload = NULL;                                                      \
        size_t reply_size = 0;                                                           \
        struct capref reply_cap = NULL_CAP;                                              \
                                                                                         \
        rpc_handler(st, recv_buf, recv_size, &reply_payload, &reply_size, recv_cap,      \
                    &reply_cap);                                                         \
                                                                                         \
        err = aos_chan_ack(chan, reply_cap, reply_payload, reply_size);                  \
        if (err_is_fail(err)) {                                                          \
            DEBUG_ERR(err, "%s: aos_chan_ack failed\n");                                 \
        }                                                                                \
                                                                                         \
        /* Clean up, regardless of err is ok or fail */                                  \
        if (reply_payload != NULL) {                                                     \
            free(reply_payload);                                                         \
        }                                                                                \
    }

#define LMP_CLEANUP(err, helper)                                                         \
    /* Deserialization cleanup */                                                        \
    err = lmp_cleanup(&helper);                                                          \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: failed to clean up\n", __func__);                            \
    }

#define LMP_RE_REGISTER(err, lc, func, arg)                                                   \
    err = lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(func, arg));       \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "%s: error re-registering handler\n", __func__);                  \
        /* Only LIB_ERR_CHAN_ALREADY_REGISTERED is possible, safe to discard it */       \
    }


#endif
