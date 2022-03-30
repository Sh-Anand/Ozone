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

#define LMP_REMAINING_SIZE (LMP_MSG_LENGTH - 2)*8


/**
 * Unified interface of sending a message.
 * @param rpc
 * @param identifier
 * @param cap
 * @param buf
 * @param size
 * @return
 * @note For M3, only sending ONE LMP message is supported. That is, size should be at
 *       most 4 * 8 - 1 = 31 bytes to fit in an LMP message (with the identifier).
 */
__attribute__((unused))
static errval_t
aos_rpc_send_general(struct aos_rpc *rpc, uint8_t identifier, struct capref cap, void *buf, size_t size, struct capref *ret_cap, void **ret_buf, size_t *ret_size) {

    // Call ONE raw LMP until success
    while() {
        // RECV
    }

    uint8_t words[LMP_MSG_LENGTH * 8];

    return SYS_ERR_NOT_IMPLEMENTED;
}

errval_t
aos_rpc_send_message(struct aos_rpc *rpc, struct aos_rpc_msg rpc_msg) {

    errval_t err;
    uintptr_t words[LMP_MSG_LENGTH];
    words[0] = rpc_msg.type;
    words[1] = rpc_msg.size;
    words[2] = 0;
    words[3] = 0;
    struct capref cap = NULL_CAP;

    //buffer fits in the remaining two words
    if(rpc_msg.size <= 16) {
        memcpy(words+2, rpc_msg.buff, rpc_msg.size);
    }

    //buffer doesn't fit, make and map frame cap
    else {
        err = frame_alloc(&cap, rpc_msg.size, NULL);
        if(err_is_fail(err))
            err_push(err, LIB_ERR_FRAME_ALLOC);
        void *addr;
        err = paging_map_frame(get_current_paging_state(), &addr, ROUND_UP(rpc_msg.size, BASE_PAGE_SIZE), cap);
        if(err_is_fail(err))
            err_push(err, LIB_ERR_PAGING_MAP);
        memcpy(addr, rpc_msg.buff, rpc_msg.size);
    }

    //send or die
    while(true) {
        err = lmp_chan_send4(rpc->chan, LMP_SEND_FLAGS_DEFAULT, cap, words[0], words[1], words[2], words[3]);

        if(lmp_err_is_transient(err))
            thread_yield(); //TODO : Does this really do what I think it does? (yields thread so another dispatcher can run immediately instead of busy waiting) there are dangers to this though, we may starve
        else
            break;
    }

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "LMP Sending failed!!!");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t
aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num) {
    // TODO: implement functionality to send a number over the channel
    // given channel and wait until the ack gets returned.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_send_string(struct aos_rpc *rpc, const char *string) {
    // TODO: implement functionality to send a string over the given channel
    // and wait for a response.

    // aos_rpc_get_ram_cap(&ram_cap);

    // aos_rpc_send_general(STRING_IDENTIFIER);

    return SYS_ERR_OK;
}


errval_t
aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                    struct capref *ret_cap, size_t *ret_bytes) {
    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.

    // aos_rpc_send_general(RAM_IDENTIFIER)

    return SYS_ERR_OK;
}


errval_t
aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc) {
    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}


errval_t
aos_rpc_serial_putchar(struct aos_rpc *rpc, char c) {
    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline,
                      coreid_t core, domainid_t *newpid) {
    // TODO (M5): implement spawn new process rpc
    return SYS_ERR_OK;
}



errval_t
aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name) {
    // TODO (M5): implement name lookup for process given a process id
    return SYS_ERR_OK;
}


errval_t
aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                             size_t *pid_count) {
    // TODO (M5): implement process id discovery
    return SYS_ERR_OK;
}



/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    //TODO: Return channel to talk to init process
    debug_printf("aos_rpc_get_init_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    //TODO: Return channel to talk to memory server process (or whoever
    //implements memory server functionality)
    debug_printf("aos_rpc_get_memory_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    //TODO: Return channel to talk to process server process (or whoever
    //implements process server functionality)
    debug_printf("aos_rpc_get_process_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    //TODO: Return channel to talk to serial driver/terminal process (whoever
    //implements print/read functionality)
    debug_printf("aos_rpc_get_serial_channel NYI\n");
    return NULL;
}

