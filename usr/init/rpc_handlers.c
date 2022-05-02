//
// Created by Zikai Liu on 4/27/22.
//

#include "rpc_handlers.h"
#include "mem_alloc.h"
#include <spawn/spawn.h>
#include <grading.h>
#include <ringbuffer/ringbuffer.h>

extern struct ring_producer *urpc_send[MAX_COREID];  // currently only for core 0 to core 1
extern struct ring_consumer *urpc_recv[MAX_COREID];  // currently only for core 0 from core 1

/*
 * Init values: *out_payload = NULL, *out_size = 0, *out_cap = NULL_CAP (nothing to reply)
 *
 * XXX: maybe init *out_payload to the buffer of LMP message, so that small message can
 * directly write to this buffer without using malloc.
 *
 * If *out_payload != NULL after return, it will be freed.
 *
 * Notice that in_size can be larger than the protocol payload (an LMP message or a page)
 * and therefore should only be used to assert out-of-bound access (check size is enough
 * rather than exact).
 */
#define HANDLER(name)                                                                    \
    static errval_t name(void *in_payload, size_t in_size, void **out_payload,           \
                         size_t *out_size, struct capref *out_cap)


#define CAST_IN_MSG(var, type)                                                           \
    if (in_size < sizeof(type)) {                                                        \
        DEBUG_PRINTF("%s: invalid payload size %lu < sizeof(%s) = %lu\n", __func__,      \
                     in_size, #type, sizeof(type));                                     \
        return LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;                                         \
    }                                                                                    \
    type *var = in_payload

#define MALLOC_OUT_MSG_WITH_SIZE(var, type, size)                                        \
    type *var = malloc(size);                                                            \
    if (var == NULL) {                                                                   \
        return LIB_ERR_MALLOC_FAIL;                                                      \
    }                                                                                    \
    *out_payload = var;                                                                  \
    *out_size = size

#define MALLOC_OUT_MSG(var, type) MALLOC_OUT_MSG_WITH_SIZE(var, type, sizeof(*var))

HANDLER(num_msg_handler)
{
    CAST_IN_MSG(num, uintptr_t);
    grading_rpc_handle_number(*num);
    DEBUG_PRINTF("Received number %lu in init\n", *num);
    return SYS_ERR_OK;
}

HANDLER(str_msg_handler)
{
    // TODO: should check against in_size against malicious calls
    CAST_IN_MSG(str, char);
    grading_rpc_handler_string(str);
    DEBUG_PRINTF("Received string in init: \"%s\"\n", str);
    return SYS_ERR_OK;
}

HANDLER(ram_request_msg_handler)
{
    CAST_IN_MSG(ram_msg, struct aos_rpc_msg_ram);
    grading_rpc_handler_ram_cap(ram_msg->size, ram_msg->alignment);
    return aos_ram_alloc_aligned(out_cap, ram_msg->size, ram_msg->alignment);
}

HANDLER(spawn_msg_handler)
{
    CAST_IN_MSG(msg, struct rpc_process_spawn_call_msg);
    grading_rpc_handler_process_spawn(msg->cmdline, msg->core);

    if (msg->core == disp_get_core_id()) {
        // Spawn on the current core

        struct spawninfo info;
        domainid_t pid;
        errval_t err = spawn_load_cmdline(msg->cmdline, &info, &pid);
        if (err_is_fail(err)) {
            return err;
        }

        MALLOC_OUT_MSG(reply, domainid_t);
        *reply = pid;
        return SYS_ERR_OK;
    } else {
        // TODO: for now only forward to core 1

        // XXX: trick to retrieve the rpc identifier
        errval_t err = ring_producer_transmit(urpc_send[msg->core], ((uint8_t *)in_payload) - 1, in_size + 1);
        if (err_is_fail(err)) {
            return err;
        }

        uint8_t *ret_payload = NULL;
        size_t ret_size;
        err = ring_consumer_recv(urpc_recv[msg->core], (void **)&ret_payload, &ret_size);
        if (err_is_fail(err)) {
            goto RET;
        }

        if (*((rpc_identifier_t *)ret_payload) == RPC_ACK_MSG) {
            MALLOC_OUT_MSG(reply, domainid_t);
            *reply = *((domainid_t *)(ret_payload + sizeof(rpc_identifier_t)));
            err = SYS_ERR_OK;
            goto RET;
        } else {
            err = *((errval_t *)(ret_payload + sizeof(rpc_identifier_t)));
            goto RET;
        }

    RET:
        free(ret_payload);
        return err;
    }
}

HANDLER(process_get_name_handler)
{
    CAST_IN_MSG(pid, domainid_t);

    char *name = NULL;
    errval_t err = spawn_get_name(*pid, &name);
    if (err_is_fail(err)) {
        return err;
    }

    *out_payload = name;  // will be freed outside
    *out_size = strlen(name) + 1;
    return SYS_ERR_OK;
}

HANDLER(process_get_all_pids_handler)
{
    grading_rpc_handler_process_get_all_pids();

    size_t count;
    domainid_t *pids;
    errval_t err = spawn_get_all_pids(&pids, &count);
    if (err_is_fail(err)) {
        return err;
    }

    MALLOC_OUT_MSG_WITH_SIZE(reply, struct rpc_process_get_all_pids_return_msg,
                             sizeof(struct rpc_process_get_all_pids_return_msg)
                                 + count * sizeof(domainid_t));
    reply->count = count;
    memcpy(reply->pids, pids, count * sizeof(domainid_t));
    free(pids);
    return SYS_ERR_OK;
}

HANDLER(terminal_handler)
{
    // FIXME: split to two messages of putchar and getchar
    CAST_IN_MSG(info, char);  // FIXME: should check for size 2 rather than 1

    errval_t err;
    if (info[0] == 0) {  // putchar
        grading_rpc_handler_serial_putchar(info[1]);
        return sys_print(info + 1, 1);  // print a single char
    } else if (info[0] == 1) {          // getchar
        char c;
        grading_rpc_handler_serial_getchar();
        err = sys_getchar(&c);
        if (err_is_fail(err)) {
            return err;
        }
        MALLOC_OUT_MSG_WITH_SIZE(reply, char, 2);
        reply[0] = 1;
        reply[1] = c;
        return SYS_ERR_OK;
    }
    return ERR_INVALID_ARGS;
}

rpc_handler_t const rpc_handlers[RPC_MSG_COUNT] = {
    [RPC_NUM] = num_msg_handler,
    [RPC_STR] = str_msg_handler,
    [RPC_RAM_REQUEST] = ram_request_msg_handler,
    [RPC_PROCESS_SPAWN] = spawn_msg_handler,
    [RPC_PROCESS_GET_NAME] = process_get_name_handler,
    [RPC_PROCESS_GET_ALL_PIDS] = process_get_all_pids_handler,
    [RPC_TERMINAL] = terminal_handler,
};