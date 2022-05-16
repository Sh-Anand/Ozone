//
// Created by Zikai Liu on 4/27/22.
//

#include "rpc_handlers.h"
#include "mem_alloc.h"
#include "mm/mm.h"
#include <aos/kernel_cap_invocations.h>
#include <spawn/spawn.h>
#include <grading.h>
#include <aos/ump_chan.h>

#include "terminal.h"

struct ump_chan *urpc_client[MAX_COREID];


extern size_t (*local_terminal_write_function)(const char*, size_t);
extern size_t (*local_terminal_read_function)(char*, size_t);

extern spinlock_t* global_print_lock;

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


    if (*((rpc_identifier_t *)ret_payload) == RPC_ACK) {
        if (ret_payload != NULL) {
            MALLOC_OUT_MSG_WITH_SIZE(reply, uint8_t, ret_size - sizeof(rpc_identifier_t));
            memcpy(reply, ret_payload + sizeof(rpc_identifier_t), ret_size - sizeof(rpc_identifier_t));
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

    // Try to get frame
    errval_t err = aos_ram_alloc_aligned(out_cap, ram_msg->size, ram_msg->alignment);
    if (err == MM_ERR_NO_MEMORY) {
        // Request RAM from core 0
        DEBUG_PRINTF("no enough memory locally, request core 0\n");

        // XXX: trick to rewrite identifier
        *(((uint8_t *)in_payload) - 1) = INTERNAL_RPC_REMOTE_RAM_REQUEST;

        // Request for twice size
        size_t original_request_size = ram_msg->size;
        ram_msg->size *= 2;

        // Request RAM from core 0
        void *reply_payload = NULL;
        size_t reply_size = 0;
        err = forward_to_core(0, in_payload, in_size, &reply_payload, &reply_size);
        if (err_is_fail(err)) {
            goto RET;
        }

        // Decode reply
        if (reply_size < sizeof(struct RAM)) {
            DEBUG_PRINTF("%s: invalid payload size %lu < sizeof(%s) = %lu\n", __func__,
                         reply_size, "struct RAM", sizeof(struct RAM));
            err = LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;
            goto RET;
        }
        struct RAM *ram = reply_payload;

        // As seen from the init ram alloc function in mem_alloc.c, we place the RAM cap
        // starting from the second slot of cnode_super
        static cslot_t forge_ram_slot = 1;
        struct capref ram_cap = { .cnode = cnode_super, .slot = forge_ram_slot++ };

        // Forge ram
        err = ram_forge(ram_cap, ram->base, ram->bytes, disp_get_current_core_id());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: failed to forge RAM");
            goto RET;
        }

        err = mm_add(&aos_mm, ram_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: mm_add failed");
            goto RET;
        }

        DEBUG_PRINTF("add RAM of size 0x%lx/0x%lx from core 0\n", ram->base, ram->bytes);

        err = aos_ram_alloc_aligned(out_cap, original_request_size, ram_msg->alignment);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: aos_ram_alloc_aligned still failed");
            goto RET;
        }

        err = SYS_ERR_OK;
    RET:
        free(reply_payload);
        return err;

    } else {
        return err;
    }
}

HANDLER(remote_ram_request_msg_handler)
{
    CAST_IN_MSG(ram_msg, struct aos_rpc_msg_ram);
    errval_t err;

    // Allocate RAM locally
    struct capref cap;
    err = aos_ram_alloc_aligned(&cap, ram_msg->size, ram_msg->alignment);
    if (err_is_fail(err)) {
        return err;
    }

    // out_cap will be discarded by UMP, must serialize
    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }
    assert(c.type == ObjType_RAM);

    MALLOC_OUT_MSG(reply, struct RAM);
    reply->base = c.u.ram.base;
    reply->bytes = c.u.ram.bytes;
    reply->pasid = c.u.ram.pasid;

    return SYS_ERR_OK;
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
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG(pid, domainid_t);

        char *name = NULL;
        errval_t err = spawn_get_name(*pid, &name);
        if (err_is_fail(err)) {
            return err;
        }

        *out_payload = name;  // will be freed outside
        *out_size = strlen(name) + 1;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

HANDLER(process_get_all_pids_handler)
{
    if (disp_get_current_core_id() == 0) {
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
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

HANDLER(terminal_getchar_handler)
{
    if (disp_get_current_core_id() == 0) {
        char c;
        grading_rpc_handler_serial_getchar();
        c = terminal_getchar();
        MALLOC_OUT_MSG(reply, char);
        *reply = c;
        return SYS_ERR_OK;
    } else {
        forward_to_core(0, in_payload, in_size, out_payload, out_size);

        return SYS_ERR_OK;
    }
}

HANDLER(terminal_putchar_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG(c, char);
		acquire_spinlock(global_print_lock);
        grading_rpc_handler_serial_putchar(*c);
		terminal_putchar(*c);
		release_spinlock(global_print_lock);
		return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

HANDLER(terminal_gets_handler)
{
	if (disp_get_core_id() == 0) {
		assert(in_size == sizeof(size_t));
		CAST_IN_MSG(len, size_t);
		char *buf = (char*)malloc(*len);
		size_t i = 0;
		for (; i < *len; i++) {
			DEBUG_PRINTF("Reading character...\n");
			buf[i] = terminal_getchar();
			if (buf[i] == '\0' || buf[i] == 0x03 || buf[i] == 0x04 || buf[i] == 0x17) break; // terminate if EOF like characters are read
		}
		*out_payload = realloc(buf, i); // in case there has been less read than requested
		if (!*out_payload) *out_payload = buf; // in case realloc failed
		*out_size = i;
		
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

HANDLER(terminal_puts_handler)
{
	if (disp_get_core_id() == 0) {
		CAST_IN_MSG(c, char);
		acquire_spinlock(global_print_lock);
		size_t i = 0;
		for (; i < in_size; i++) {
			if (c[i] == 0) break;
			grading_rpc_handler_serial_putchar(c[i]);
			terminal_putchar(c[i]);
		}
		release_spinlock(global_print_lock);
		MALLOC_OUT_MSG_WITH_SIZE(len, size_t, sizeof(size_t));
		*len = i;
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

rpc_handler_t const rpc_handlers[INTERNAL_RPC_MSG_COUNT] = {
    [RPC_NUM] = num_msg_handler,
    [RPC_STR] = str_msg_handler,
    [RPC_RAM_REQUEST] = ram_request_msg_handler,
    [RPC_PROCESS_SPAWN] = spawn_msg_handler,
    [RPC_PROCESS_GET_NAME] = process_get_name_handler,
    [RPC_PROCESS_GET_ALL_PIDS] = process_get_all_pids_handler,
	[RPC_STRESS] = stress_test_handler,
    [RPC_TERMINAL_GETCHAR] = terminal_getchar_handler,
    [RPC_TERMINAL_PUTCHAR] = terminal_putchar_handler,
	[RPC_TERMINAL_GETS] = terminal_gets_handler,
	[RPC_TERMINAL_PUTS] = terminal_puts_handler,
    [INTERNAL_RPC_REMOTE_RAM_REQUEST] = remote_ram_request_msg_handler,
};