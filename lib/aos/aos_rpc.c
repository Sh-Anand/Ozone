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

struct capref rpc_reserved_recv_slot;  // all 0 is NULL_CAP
static bool recv_slot_not_refilled = false;

static struct thread_mutex reserved_slot_mutex;  // protect rpc_reserved_recv_slot

#define LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE                                                  \
    (LMP_MSG_LENGTH * sizeof(uintptr_t) - sizeof(rpc_identifier_t))


errval_t lmp_serialize(rpc_identifier_t identifier, struct capref cap, void *buf,
                       size_t size, uintptr_t ret_payload[LMP_MSG_LENGTH],
                       struct capref *ret_cap, struct lmp_helper *helper)
{
    errval_t err;

    if (buf == NULL && size != 0) {
        return ERR_INVALID_ARGS;
    }

    if (size <= LMP_SINGLE_MSG_MAX_PAYLOAD_SIZE) {
        // Buffer fits in the remaining space
        *((rpc_identifier_t *)ret_payload) = identifier;
        memcpy(((uint8_t *)ret_payload) + sizeof(rpc_identifier_t), buf, size);
        *ret_cap = cap;

        helper->payload_frame = NULL_CAP;
        helper->mapped_frame = NULL;

    } else {
        // Buffer doesn't fit, make and map frame cap
#if 1
        DEBUG_PRINTF("lmp_serialize: alloc frame\n");
#endif

        if (!capref_is_null(cap)) {
            return LIB_ERR_RPC_LARGE_MSG_WITH_CAP;
        }

        size_t rounded_size = ROUND_UP(size + sizeof(size_t) + sizeof(rpc_identifier_t),
                                       BASE_PAGE_SIZE);

        struct capref frame_cap;
        err = frame_alloc(&frame_cap, rounded_size, NULL);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_FRAME_ALLOC);
        }

        uint8_t *addr;
        err = paging_map_frame(get_current_paging_state(), (void **)&addr, rounded_size,
                               frame_cap);
        if (err_is_fail(err)) {
            err_push(err, LIB_ERR_PAGING_MAP);
        }

        *((size_t *)addr) = size;
        // Put identifier before actual payload, consistent with single message
        *((rpc_identifier_t *)(addr + sizeof(size_t))) = identifier;
        memcpy(addr + sizeof(size_t) + sizeof(rpc_identifier_t), buf, size);

        *((rpc_identifier_t *)ret_payload) = RPC_MSG_IN_FRAME;  // replace the identifier
        *ret_cap = frame_cap;

        helper->payload_frame = frame_cap;
        helper->mapped_frame = addr;
    }

    return SYS_ERR_OK;
}

errval_t lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref recv_cap,
                         rpc_identifier_t *ret_type, uint8_t **ret_buf, size_t *ret_size,
                         struct lmp_helper *helper)
{
    errval_t err;

    rpc_identifier_t type = *((rpc_identifier_t *)recv_msg->words);
    uint8_t *buf;
    size_t size;

    uint8_t *frame_payload = NULL;

    if (type == RPC_MSG_IN_FRAME) {
        assert(!capref_is_null(recv_cap));

#if 1
        DEBUG_PRINTF("lmp_deserialize: trying to map received frame in local space\n");
#endif

        struct frame_identity frame_id;
        err = frame_identify(recv_cap, &frame_id);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_FRAME_IDENTIFY);
        }

        err = paging_map_frame(get_current_paging_state(), (void **)&frame_payload,
                               frame_id.bytes, recv_cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_MAP);
        }

        size = *((size_t *)frame_payload);
        type = *((rpc_identifier_t *)(frame_payload + sizeof(size_t)));  // replace
        buf = frame_payload + sizeof(size_t) + sizeof(rpc_identifier_t);

        helper->payload_frame = recv_cap;
        helper->mapped_frame = frame_payload;

    } else {
        buf = ((uint8_t *)recv_msg->words) + sizeof(rpc_identifier_t);
        size = recv_msg->buf.msglen * (sizeof(uintptr_t)) - sizeof(rpc_identifier_t);

        helper->payload_frame = NULL_CAP;
        helper->mapped_frame = NULL;
    }

    *ret_type = type;
    *ret_buf = buf;
    *ret_size = size;
    return SYS_ERR_OK;
}

errval_t lmp_cleanup(struct lmp_helper *helper)
{
    if (helper->mapped_frame != NULL) {
        assert(!capref_is_null(helper->payload_frame));

        errval_t err;
        err = paging_unmap(get_current_paging_state(), helper->mapped_frame);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_PAGING_UNMAP);
        }
        err = cap_destroy(helper->payload_frame);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_DESTROY);
        }

    } else {
        assert(capref_is_null(helper->payload_frame));
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

static errval_t rpc_lmp_call_general(struct lmp_chan *lc, rpc_identifier_t identifier,
                                     struct capref call_cap, void *call_buf,
                                     size_t call_size, struct capref *ret_cap,
                                     void **ret_buf, size_t *ret_size)
{
    errval_t err;

    if (reserved_slot_is_null_thread_safe()) {
        // This can happen when the current send is triggered by a slot refill
        // In this case, slot allocator is willing to give out a slot as its internal
        // refill flag is set
        err = refill_reserved_slot_thread_safe();
        if (err_is_fail(err)) {
            DEBUG_PRINTF("rpc_lmp_call_general: failed to alloc "
                         "rpc_reserved_recv_slot\n");
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }
    }


    uintptr_t send_words[LMP_MSG_LENGTH];
    struct capref send_cap;
    struct lmp_helper send_helper;

    // marshall arguments into buffer/frame
    err = lmp_serialize(identifier, call_cap, call_buf, call_size, send_words, &send_cap, &send_helper);

    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    // send or die
    while (true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, send_cap, send_words[0],
                             send_words[1], send_words[2], send_words[3]);

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
        DEBUG_ERR(err, "rpc_lmp_call_general: failed to send\n");
        return err;
    }

    err = lmp_cleanup(&send_helper);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "rpc_lmp_call_general: failed to cleanup send_helper\n");
        // Continue
    }

    // Receive acknowledgement and/or return message
    struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;
    while (true) {
        err = lmp_chan_recv(lc, &recv_msg, &recv_cap);
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
        // This can happen when the current call results from slot_alloc
        if (!reserved_slot_is_null_thread_safe()) {
            THREAD_MUTEX_ENTER(&reserved_slot_mutex)
            {
                // Use the reserved slot first, since slot_alloc can trigger a refill
                // which calls rpc ram alloc, and then we have no slot to receive the call_cap
                lmp_chan_set_recv_slot(lc, rpc_reserved_recv_slot);
                rpc_reserved_recv_slot = NULL_CAP;
            }
            THREAD_MUTEX_EXIT(&reserved_slot_mutex)

            // Refill rpc_reserved_recv_slot
            err = refill_reserved_slot_thread_safe();
            if (err_is_fail(err)) {
                DEBUG_PRINTF("rpc_lmp_call_general: failed to alloc "
                             "rpc_reserved_recv_slot\n");
                return err_push(err, LIB_ERR_SLOT_ALLOC);
            }

            if (recv_slot_not_refilled) {
                err = lmp_chan_alloc_recv_slot(lc);
                if (err_is_fail(err)) {
                    return err;
                }
            }

        } else {
            recv_slot_not_refilled = true;
        }
    }

    rpc_identifier_t recv_type;
    uint8_t *recv_buf;
    size_t recv_size;
    struct lmp_helper recv_helper;

    err = lmp_deserialize(&recv_msg, recv_cap, &recv_type, &recv_buf, &recv_size, &recv_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_DESERIALIZE);
    }

    if (recv_type == RPC_ACK) {
        if (ret_buf) {
            *ret_buf = malloc(recv_size);
            memcpy(*ret_buf, recv_buf, recv_size);
        }

        if (ret_size) {
            *ret_size = recv_size;
        }

        if (!capref_is_null(recv_cap)) {
            if (ret_cap) {
                *ret_cap = recv_cap;
            } else {
                DEBUG_PRINTF("rpc_lmp_call_general: received a cap but is given up!\n");
            }
        }
        err = SYS_ERR_OK;

    } else if (recv_type == RPC_ERR) {
        err = *((errval_t *)recv_buf);

    } else {
        DEBUG_PRINTF("rpc_lmp_call_general: unknown recv_type %u\n", recv_type);
        err = LIB_ERR_RPC_INVALID_MSG;
    }


    // Unmap frame if needed
    errval_t err2 = lmp_cleanup(&recv_helper);
    if (err_is_fail(err2)) {
        DEBUG_ERR(err2, "rpc_lmp_call_general: failed to clean up\n");
        // Don't touch err
    }

    return err;
}

static errval_t rpc_lmp_respond(struct lmp_chan *lc, uint8_t identifier,
                                struct capref cap, void *buf, size_t size)
{
    errval_t err;
    uintptr_t words[LMP_MSG_LENGTH];
    struct lmp_helper serialization_helper;

    struct capref send_cap;
    err = lmp_serialize(identifier, cap, buf, size, words, &send_cap,
                        &serialization_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_SERIALIZE);
    }

    // Send or die
    while (true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, cap, words[0], words[1],
                             words[2], words[3]);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                thread_yield();
            } else {
                return err_push(err, LIB_ERR_LMP_CHAN_SEND);
            }
        } else {
            break;
        }
    }

    // Clean up
    err = lmp_cleanup(&serialization_helper);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CLEANUP);
    }

    return SYS_ERR_OK;
}

errval_t aos_chan_call(struct aos_chan *chan, rpc_identifier_t identifier,
                              struct capref call_cap, void *call_buf, size_t call_size,
                              struct capref *ret_cap, void **ret_buf, size_t *ret_size)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_call_general(&chan->lc, identifier, call_cap, call_buf,
                                    call_size, ret_cap, ret_buf, ret_size);
    case AOS_CHAN_TYPE_UMP:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"aos_chan_nack: unknown chan->type");
    }
}

errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, void *buf, size_t size)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_respond(&chan->lc, RPC_ACK, cap, buf, size);
    case AOS_CHAN_TYPE_UMP:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"aos_chan_nack: unknown chan->type");
    }
}

errval_t aos_chan_nack(struct aos_chan *chan, errval_t err)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_respond(&chan->lc, RPC_ERR, NULL_CAP, &err, sizeof(errval_t));
    case AOS_CHAN_TYPE_UMP:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"aos_chan_nack: unknown chan->type");
    }
}


errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err = aos_rpc_call(rpc, RPC_NUM, NULL_CAP, &num, sizeof(num), NULL, NULL,
                                NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RPC_SEND_NUM);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err = aos_rpc_call(rpc, RPC_STR, NULL_CAP, (void *)string,
                                strlen(string) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RPC_SEND_STR);
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_stress_test(struct aos_rpc *rpc, uint8_t *val, size_t len)
{
    errval_t err = aos_rpc_call(rpc, RPC_STRESS_TEST, NULL_CAP, (void *)val, len, NULL,
                                NULL, NULL);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_RPC_SEND_STR);

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
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
            return err_push(err, MM_ERR_INVALID_CAP);
        }
        assert(c.type == ObjType_RAM);
        assert(c.u.ram.bytes >= bytes);
        *ret_bytes = c.u.ram.bytes;
    }

    // aos_rpc_call(RAM_IDENTIFIER)

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

errval_t aos_rpc_init(struct aos_rpc *rpc)
{
    assert(rpc->chan.type == AOS_CHAN_TYPE_LMP);
    errval_t err;

    thread_mutex_init(&reserved_slot_mutex);

    err = lmp_chan_alloc_recv_slot(&rpc->chan.lc);
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