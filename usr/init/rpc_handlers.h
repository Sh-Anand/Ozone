//
// Created by Zikai Liu on 4/27/22.
//

#ifndef AOS_RPC_HANDLERS_H
#define AOS_RPC_HANDLERS_H

#include <aos/aos_rpc.h>

typedef errval_t (*rpc_handler_t)(void *in_payload, size_t in_size, void **out_payload, size_t *out_size, struct capref *out_cap);

extern rpc_handler_t const rpc_handlers[RPC_MSG_COUNT];

#endif  // AOS_RPC_HANDLERS_H
