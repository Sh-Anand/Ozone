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

#define LMP_REMAINING_SIZE (LMP_MSG_LENGTH - 1) * 8

// ret_cap returns a pointer to a new frame cap if assigned, otherwise just returns the
// sent cap back words is an array of LMP_MSG_LENGTH size
errval_t rpc_marshall(enum msg_type identifier, struct capref cap_ref, void *buf,
                      size_t size, uintptr_t *words, struct capref *ret_cap)
{
    errval_t err;
    struct capref cap = cap_ref;

    char *buffer = (char *)words;
    buffer[0] = identifier;
    buffer++;
    size_t remaining_space = LMP_MSG_LENGTH * 8 - 1;

    // encode size if string message
    if (identifier == STR_MSG) {
        memcpy(buffer, &size, sizeof(size_t));
        buffer += sizeof(size_t);
        remaining_space -= sizeof(size_t);
    }

    if (size <= remaining_space) {
        // buffer fits in the remaining space
        memcpy(buffer, buf, size);
    } else {
        // buffer doesn't fit, make and map frame cap
        DEBUG_PRINTF("rpc_marshall: alloc frame\n")

        struct capref frame_cap;
        err = frame_alloc(&frame_cap, size, NULL);
        if (err_is_fail(err))
            err_push(err, LIB_ERR_FRAME_ALLOC);
        void *addr;
        err = paging_map_frame(get_current_paging_state(), &addr,
                               ROUND_UP(size, BASE_PAGE_SIZE), frame_cap);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_PAGING_MAP);
        }
        memcpy(addr, buf, size);
        cap = frame_cap;
    }

    *ret_cap = cap;

    return SYS_ERR_OK;
}

/**
 * Unified interface of sending a message.
 * @param rpc
 * @param identifier
 * @param cap
 * @param buf
 * @param size
 * @param ret_cap
 * @param ret_buf     Should be freed outside.
 * @param ret_size
 * @return
 * @note For M3, only sending ONE LMP message is supported. That is, size should be at
 *       most 4 * 8 - 1 = 31 bytes to fit in an LMP message (with the identifier).
 */
static errval_t aos_rpc_send_general(struct aos_rpc *rpc, enum msg_type identifier,
                                     struct capref cap, void *buf, size_t size,
                                     struct capref *ret_cap, void **ret_buf,
                                     size_t *ret_size)
{
    errval_t err;
    uintptr_t words[LMP_MSG_LENGTH];
    struct capref send_cap;

    // marshall arguments into buffer/frame
    err = rpc_marshall(identifier, cap, buf, size, words, &send_cap);

    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MARSHALL_FAIL);
    }

    // send or die
    while (true) {
        err = lmp_chan_send4(rpc->chan, LMP_SEND_FLAGS_DEFAULT, send_cap, words[0],
                             words[1], words[2], words[3]);

        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                thread_yield();  // TODO : Does this really do what I think it does?
                                 // (yields thread so another dispatcher can run
                                 // immediately instead of busy waiting) there are dangers
                                 // to this though, we may starve
            } else {
                return err;
            }
        } else {
            break;
        }
    }

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "LMP Sending failed!!!");
        return err;
    }

    // receive acknowledgement/return message
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;
    while (true) {
        err = lmp_chan_recv(rpc->chan, &msg, &recv_cap);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_NO_LMP_MSG) {
                thread_yield();  // TODO verify if this works
            } else {
                return err;
            }
        } else {
            break;
        }
    }

    if (!capref_is_null(recv_cap)) {
        if (ret_cap) {
            *ret_cap = recv_cap;
        } else {
            DEBUG_PRINTF("warning: aos_rpc_send_general received a cap which is given "
                         "up\n");
        }
        err = slot_alloc(&recv_cap);
        if (err_is_fail(err)) {
            return err;
        }
        lmp_chan_set_recv_slot(rpc->chan, recv_cap);
    }

    if (ret_buf) {
        void *res_buf = malloc((msg.buf.msglen * sizeof(uintptr_t)) - 1);
        memcpy(res_buf, ((char *)msg.words + 1), msg.buf.msglen * sizeof(uintptr_t));
        *ret_buf = res_buf;
    }

    if (ret_size) {
        *ret_size = msg.buf.msglen;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err = aos_rpc_send_general(rpc, NUM_MSG, NULL_CAP, &num, sizeof(num), NULL,
                                        NULL, NULL);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_RPC_SEND_NUM);

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err = aos_rpc_send_general(rpc, STR_MSG, NULL_CAP, (void *)string,
                                        strlen(string), NULL, NULL, NULL);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_RPC_SEND_STR);

    return SYS_ERR_OK;
}


errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.

    // aos_rpc_send_general(RAM_IDENTIFIER)

    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core,
                               domainid_t *newpid)
{
    size_t call_msg_size = sizeof(struct rpc_process_spawn_call_msg) + strlen(cmdline) + 1;
    struct rpc_process_spawn_call_msg *call_msg = calloc(call_msg_size, 1);
    call_msg->core = core;
    strcpy(call_msg->cmdline, cmdline);

    struct rpc_process_spawn_return_msg *return_msg = NULL;
    errval_t err = aos_rpc_send_general(rpc, RPC_PROCESS_SPAWN_MSG, NULL_CAP, call_msg,
                                        call_msg_size, NULL, (void **)&return_msg, NULL);
    if (err_is_ok(err)) {
        *newpid = return_msg->pid;
    }  // on failure, fall through

    free(call_msg);
    free(return_msg);
    return err;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    struct rpc_process_get_name_call_msg call_msg = {.pid = pid};
    struct rpc_process_get_name_return_msg *return_msg = NULL;
    errval_t err = aos_rpc_send_general(rpc, RPC_PROCESS_GET_NAME_MSG, NULL_CAP, &call_msg,
                                        sizeof(call_msg), NULL, (void **)&return_msg, NULL);
    if (err_is_ok(err)) {
        *name = strdup(return_msg->name);
    }  // on failure, fall through

    free(return_msg);
    return err;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    struct rpc_process_get_all_pids_return_msg *return_msg = NULL;
    size_t return_size = 0;
    errval_t err = aos_rpc_send_general(rpc, RPC_PROCESS_GET_ALL_PIDS_MSG, NULL_CAP, NULL,
                                        0, NULL, (void **)&return_msg, &return_size);
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
    return aos_rpc_get_init_channel();
}
