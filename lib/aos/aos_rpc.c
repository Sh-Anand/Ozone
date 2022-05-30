/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/capabilities.h>

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err = aos_rpc_call(rpc, RPC_NUM, NULL_CAP, &num, sizeof(num), NULL, NULL,
                                NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err = aos_rpc_call(rpc, RPC_STR, NULL_CAP, (void *)string,
                                strlen(string) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_stress_test(struct aos_rpc *rpc, uint8_t *val, size_t len)
{
    errval_t err = aos_rpc_call(rpc, RPC_STRESS_TEST, NULL_CAP, (void *)val, len, NULL,
                                NULL, NULL);
    if (err_is_fail(err))
        return err;

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: start\n");
    struct aos_rpc_msg_ram msg = { .size = bytes, .alignment = alignment };
    errval_t err = aos_rpc_call(rpc, RPC_RAM_REQUEST, NULL_CAP, &msg, sizeof(msg),
                                ret_cap, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive RAM\n");
        return err;
    }

    if (ret_bytes != NULL) {
        // No better way as of now (mm does not return any size)
        struct capability c;
        err = cap_direct_identify(*ret_cap, &c);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to get the frame info\n");
            return err_push(err, LIB_ERR_CAP_IDENTIFY);
        }
        assert(c.type == ObjType_RAM);
        assert(c.u.ram.bytes >= bytes);
        *ret_bytes = c.u.ram.bytes;
    }
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: done\n");
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;
    char *ret_char = NULL;
    size_t ret_size = 0;
    err = aos_rpc_call(rpc, RPC_TERMINAL_GETCHAR, NULL_CAP, NULL, 0, NULL,
                       (void **)&ret_char, &ret_size);
    if (err_is_ok(err)) {
        assert(ret_size >= sizeof(char));
        *retc = *ret_char;
        // printf("retc: %c (err: %d)\n", *retc, err);
    }
    free(ret_char);
    return err;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // we don't care about return values or capabilities, just send this single char
    // (again, do better)
    // sys_print("aos_rpc_serial_putchar called!\n", 32);
    errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_PUTCHAR, NULL_CAP, &c, sizeof(char),
                                NULL, NULL, NULL);

    return err;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    size_t call_msg_size = sizeof(struct rpc_process_spawn_call_msg) + strlen(cmdline) + 1;
    struct rpc_process_spawn_call_msg *call_msg = calloc(call_msg_size, 1);
    call_msg->core = core;
    strcpy(call_msg->cmdline, cmdline);

    domainid_t *return_pid = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_SPAWN, NULL_CAP, call_msg, call_msg_size,
                                NULL, (void **)&return_pid, NULL);
    if (err_is_ok(err)) {
        *newpid = *return_pid;
    }  // on failure, fall through

    free(call_msg);
    free(return_pid);
    return err;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    char *return_msg = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_NAME, NULL_CAP, &pid,
                                sizeof(domainid_t), NULL, (void **)&return_msg, NULL);
    if (err_is_fail(err)) {
        free(return_msg);
        return err;
    }
    *name = return_msg;
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    struct rpc_process_get_all_pids_return_msg *return_msg = NULL;
    size_t return_size = 0;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_ALL_PIDS, NULL_CAP, NULL, 0, NULL,
                                (void **)&return_msg, &return_size);
    if (err_is_ok(err)) {
        *pid_count = return_msg->count;
        *pids = malloc(return_msg->count * sizeof(domainid_t));
        if (*pids == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(*pids, return_msg->pids, return_msg->count * sizeof(domainid_t));
    }  // on failure, fall through

    free(return_msg);
    return err;
}


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    // debug_printf("aos_rpc_get_serial_channel NYI\n");
    return aos_rpc_get_init_channel();  // XXX: For now return the init channel, since the
                                        // current serial driver is handled in init
}