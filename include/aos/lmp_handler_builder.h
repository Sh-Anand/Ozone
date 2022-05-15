//
// Created by Zikai Liu on 5/15/22.
//

#ifndef AOS_LMP_HANDLER_BUILDER_H
#define AOS_LMP_HANDLER_BUILDER_H

#define LMP_HANDLER_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type,  \
                                            recv_buf, recv_size, helper, RE_REGISTER,    \
                                            FAILURE)                                     \
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

#define LMP_HANDLER_TRY_SETUP_BINDING(err, lc, recv_cap, FAILURE)                        \
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


#define LMP_HANDLER_CLEANUP(err, helper)                                                 \
    /* Deserialization cleanup */                                                        \
    err = lmp_cleanup(&helper);                                                          \
    if (err_is_fail(err)) {                                                              \
        DEBUG_ERR(err, "rpc_lmp_handler: failed to clean up\n");                         \
    }

#endif
