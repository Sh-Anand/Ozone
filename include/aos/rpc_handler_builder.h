//
// Created by Zikai Liu on 4/27/22.
//

#ifndef AOS_RPC_HANDLER_BUILDER_H
#define AOS_RPC_HANDLER_BUILDER_H

#include <aos/rpc.h>

typedef errval_t (*rpc_handler_t)(void *arg, void *in_payload, size_t in_size,
                                  void **out_payload, size_t *out_size,
                                  struct capref in_cap, struct capref *out_cap);

/*
 * Init values: *out_payload = NULL, *out_size = 0, *out_cap = NULL_CAP (nothing to reply)
 *
 * XXX: maybe init *out_payload to the buffer of LMP message, so that small message can
 * directly write to this buffer without using malloc.
 *
 * If *out_payload != NULL after return, it will be freed.
 */
#define RPC_HANDLER(name)                                                                 \
    static errval_t name(void *arg, void *in_payload, size_t in_size, void **out_payload, \
                         size_t *out_size, struct capref in_cap, struct capref *out_cap)

#define ASSERT_ZERO_IN_SIZE                                                              \
    do {                                                                                 \
        if (in_size != 0) {                                                              \
            DEBUG_PRINTF("%s: payload size %lu != 0\n", __func__, in_size);              \
            return LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;                                     \
        }                                                                                \
    } while (0)

#define CAST_IN_MSG_NO_CHECK(var, type) type *var = in_payload

#define CAST_IN_MSG_AT_LEAST_SIZE(var, type)                                             \
    if (in_size < sizeof(type)) {                                                        \
        DEBUG_PRINTF("%s: invalid payload size %lu < sizeof(%s) (%lu)\n", __func__,      \
                     in_size, #type, sizeof(type));                                      \
        return LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;                                         \
    }                                                                                    \
    type *var = in_payload

#define CAST_EXACT_SIZE(payload, size, var, type)                                        \
    if (size != sizeof(type)) {                                                          \
        DEBUG_PRINTF("%s: invalid payload size %lu != sizeof(%s) (%lu)\n", __func__,     \
                     in_size, #type, sizeof(type));                                      \
        return LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;                                         \
    }                                                                                    \
    type *var = payload

#define CAST_IN_MSG_EXACT_SIZE(var, type) CAST_EXACT_SIZE(in_payload, in_size, var, type)

#define MALLOC_WITH_SIZE(var, type, size)                                                \
    type *var = malloc(size);                                                            \
    if (var == NULL) {                                                                   \
        return LIB_ERR_MALLOC_FAIL;                                                      \
    }

#define MALLOC_EXACT_SIZE(var, type) MALLOC_WITH_SIZE(var, type, sizeof(type))

#define MALLOC_OUT_MSG_WITH_SIZE(var, type, size)                                        \
    MALLOC_WITH_SIZE(var, type, size)                                                    \
    *out_payload = var;                                                                  \
    *out_size = size

#define MALLOC_OUT_MSG(var, type) MALLOC_OUT_MSG_WITH_SIZE(var, type, sizeof(*var))

#endif  // AOS_RPC_HANDLER_BUILDER_H
