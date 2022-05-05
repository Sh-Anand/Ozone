//
// Created by Zikai Liu on 4/27/22.
//

#include "rpc_handlers.h"
#include "mem_alloc.h"
#include <spawn/spawn.h>
#include <grading.h>
#include <aos/ump_chan.h>

struct ump_chan *urpc_client[MAX_COREID];

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
                     in_size, #type, sizeof(type));                                      \
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

static errval_t forward_to_core(coreid_t core, void *in_payload, size_t in_size,
                                void **out_payload, size_t *out_size)
{
    // XXX: trick to retrieve the rpc identifier
    errval_t err = ring_producer_send(&urpc_client[core]->send,
                                      ((uint8_t *)in_payload) - 1, in_size + 1);
    if (err_is_fail(err)) {
        return err;
    }

    uint8_t *ret_payload = NULL;
    size_t ret_size = 0;
    err = ring_consumer_recv(&urpc_client[core]->recv, (void **)&ret_payload, &ret_size);
    if (err_is_fail(err)) {
        goto RET;
    }

    if (*((rpc_identifier_t *)ret_payload) == RPC_ACK_MSG) {
        if (ret_payload != NULL) {
            MALLOC_OUT_MSG_WITH_SIZE(reply, uint8_t, ret_size - sizeof(rpc_identifier_t));
            memcpy(reply, ret_payload, ret_size - sizeof(rpc_identifier_t));
        }
        err = SYS_ERR_OK;
        goto RET;
    } else {
        assert(ret_size == sizeof(rpc_identifier_t) + sizeof(errval_t));
        err = *((errval_t *)(ret_payload + sizeof(rpc_identifier_t)));
        goto RET;
    }

RET:
    free(ret_payload);
    return err;
}

HANDLER(stress_test_handler)
{
	if (disp_get_current_core_id() == 0) {
		CAST_IN_MSG(vals, uint8_t);
		size_t len = in_size;
		for (uint8_t i = 0; len < in_size; i++, len++) {
			if (vals[len] != i) goto error;
		}
		return SYS_ERR_OK;
		error:
		DEBUG_PRINTF("STRESS TEST RECEIVED CORRUPTED DATA!\n");
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

HANDLER(num_msg_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG(num, uintptr_t);
        grading_rpc_handle_number(*num);
        DEBUG_PRINTF("Received number %lu\n", *num);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

HANDLER(str_msg_handler)
{
    if (disp_get_current_core_id() == 0) {
        // TODO: should check against in_size against malicious calls
        CAST_IN_MSG(str, char);
        grading_rpc_handler_string(str);
        int len = printf("Received string: \"%s\"\n", str);
		printf("Printed %d characters\n", len);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
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
        return forward_to_core(msg->core, in_payload, in_size, out_payload, out_size);
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
	[RPC_STRESS] = stress_test_handler
};