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

#define LMP_REMAINING_SIZE (LMP_MSG_LENGTH - 1) * 8

struct capref rpc_reserved_recv_slot;  // all 0 is NULL_CAP
static bool recv_slot_not_refilled = false;

static struct thread_mutex reserved_slot_mutex;  // protect rpc_reserved_recv_slot

// ret_cap returns a pointer to a new frame cap if assigned, otherwise just returns the
// sent cap back words is an array of LMP_MSG_LENGTH size
errval_t rpc_marshall(uint8_t identifier, struct capref cap, void *buf, size_t size,
                      uintptr_t *words, struct capref *ret_cap)
{
    errval_t err;

    uint8_t *buffer = (uint8_t *)words;
    buffer[0] = identifier;
    buffer++;

    *ret_cap = cap;

    if (buf == NULL) {
        if (size == 0) {
            return SYS_ERR_OK;
        } else {
            return ERR_INVALID_ARGS;
        }
    }


    size_t remaining_space = LMP_MSG_LENGTH * 8 - 1;
    if (size <= remaining_space) {
        // Buffer fits in the remaining space
        memcpy(buffer, buf, size);

    } else {
        // Buffer doesn't fit, make and map frame cap
        DEBUG_PRINTF("rpc_marshall: alloc frame\n")

        if (!capref_is_null(cap)) {
            return LIB_ERR_RPC_LARGE_MSG_WITH_CAP;
        }

        size_t rounded_size = ROUND_UP(size, BASE_PAGE_SIZE);

        struct capref frame_cap;
        err = frame_alloc(&frame_cap, rounded_size, NULL);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_FRAME_ALLOC);
        }

        void *addr;
        err = paging_map_frame(get_current_paging_state(), &addr, rounded_size, frame_cap);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_PAGING_MAP);
        }
        memcpy(addr, buf, size);
        *ret_cap = frame_cap;
    }

    return SYS_ERR_OK;
}

static bool reserved_slot_is_null_thread_safe(void)
{
    bool reserved_slot_is_null;
    THREAD_MUTEX_ENTER(&reserved_slot_mutex)
    {
        reserved_slot_is_null = (capref_is_null(rpc_reserved_recv_slot));
    }
    THREAD_MUTEX_EXIT(&reserved_slot_mutex)
    return reserved_slot_is_null;
}

static errval_t refill_reserved_slot_thread_safe(void)
{
    struct capref slot = NULL_CAP;
    errval_t err = slot_alloc(&slot);
    // Cannot lock on slot_alloc since it may trigger refill, use a local variable instead

    THREAD_MUTEX_ENTER(&reserved_slot_mutex)
    {
        rpc_reserved_recv_slot = slot;
    }
    THREAD_MUTEX_EXIT(&reserved_slot_mutex)

    return err;
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

    if (reserved_slot_is_null_thread_safe()) {
        // This can happen when the current send is triggered by a slot refill
        // In this case, slot allocator is willing to give out a slot as its internal
        // refill flag is set
        err = refill_reserved_slot_thread_safe();
        if (err_is_fail(err)) {
            debug_printf("failed to alloc rpc_reserved_recv_slot\n");
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }
    }


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
                thread_yield();
            } else {
                return err;
            }
        } else {
            break;
        }
    }

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_send_general: failed to send\n");
        return err;
    }

    // receive acknowledgement/return message
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;
    while (true) {
        err = lmp_chan_recv(rpc->chan, &msg, &recv_cap);
        if (err_is_fail(err)) {
            if (err == LIB_ERR_NO_LMP_MSG) {
                thread_yield();
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
            DEBUG_PRINTF("aos_rpc_send_general received a cap but is given up!\n");
        }

        // This can happen when the current call results from slot_alloc
        if (!reserved_slot_is_null_thread_safe()) {

            THREAD_MUTEX_ENTER(&reserved_slot_mutex)
            {
                // Use the reserved slot first, since slot_alloc can trigger a refill
                // which calls rpc ram alloc, and then we have no slot to receive the cap
                lmp_chan_set_recv_slot(rpc->chan, rpc_reserved_recv_slot);
                rpc_reserved_recv_slot = NULL_CAP;
            }
            THREAD_MUTEX_EXIT(&reserved_slot_mutex)

            // Refill rpc_reserved_recv_slot
            err = refill_reserved_slot_thread_safe();
            if (err_is_fail(err)) {
                debug_printf("failed to alloc rpc_reserved_recv_slot\n");
                return err_push(err, LIB_ERR_SLOT_ALLOC);
            }

            if (recv_slot_not_refilled) {
                err = lmp_chan_alloc_recv_slot(rpc->chan);
                if (err_is_fail(err)) {
                    return err;
                }
            }

        } else {
            recv_slot_not_refilled = true;
        }
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
    //    if (refilling_recv_slot) {
    //        assert(bytes == BASE_PAGE_SIZE);
    //        *ret_cap = reserved_slot;
    //        if (ret_bytes != NULL)  {
    //            *ret_bytes = BASE_PAGE_SIZE;
    //        }
    //        reserved_slot = NULL_CAP;
    //        return SYS_ERR_OK;
    //    }


    struct aos_rpc_msg_ram msg = { .size = bytes, .alignment = alignment };
    errval_t err = aos_rpc_send_general(rpc, RAM_MSG, NULL_CAP, &msg, sizeof(msg),
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
            return err_push(err, MM_ERR_INVALID_CAP);
        }
        assert(c.type == ObjType_RAM);
        assert(c.u.ram.bytes >= bytes);
        *ret_bytes = c.u.ram.bytes;
    }

    // aos_rpc_send_general(RAM_IDENTIFIER)

    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.
    errval_t err;

    // TODO: this is no good, do better
    // a bit of packaged info: 0 in the first place is a putchar, 1 is a getchar
    char info[2] = { 1, 0 };
    char *ret_info;
    size_t rsize;
    err = aos_rpc_send_general(rpc, TERMINAL_MSG, NULL_CAP, info, 2, NULL,
                               (void **)&ret_info, &rsize);
    assert(rsize >= 2);

    *retc = ret_info[1];  // pass the returned character along
                          // printf("retc: %c (err: %d)\n", *retc, err);

    return err;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.

    // TODO: this is no good, do better
    // a bit of packaged info: 0 in the first place is a putchar, 1 is a getchar
    char data[2] = { 0, c };

    // we don't care about return values or capabilities, just send this single char
    // (again, do better)
    // sys_print("aos_rpc_serial_putchar called!\n", 32);
    errval_t err = aos_rpc_send_general(rpc, TERMINAL_MSG, NULL_CAP, data, 2, NULL, NULL,
                                        NULL);

    return err;
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
    struct rpc_process_get_name_call_msg call_msg = { .pid = pid };
    struct rpc_process_get_name_return_msg *return_msg = NULL;
    errval_t err = aos_rpc_send_general(rpc, RPC_PROCESS_GET_NAME_MSG, NULL_CAP,
                                        &call_msg, sizeof(call_msg), NULL,
                                        (void **)&return_msg, NULL);
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
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    // debug_printf("aos_rpc_get_serial_channel NYI\n");
    return aos_rpc_get_init_channel();  // XXX: For now return the init channel, since the
                                        // current serial driver is handled in init
}

errval_t aos_rpc_init(struct aos_rpc *rpc)
{
    errval_t err;

    thread_mutex_init(&reserved_slot_mutex);

    err = lmp_chan_alloc_recv_slot(rpc->chan);
    if (err_is_fail(err)) {
        return err;
    }

    err = slot_alloc(&rpc_reserved_recv_slot);  // allocate reserved slot
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    /* set init RPC client in our program state */
    set_init_rpc(rpc);

    return SYS_ERR_OK;
}