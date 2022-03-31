/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading.h>

#include "mem_alloc.h"
#include <spawn/spawn.h>



struct bootinfo *bi;

coreid_t my_core_id;

/**
 * @brief TODO: make use of this function
 * 
 * @param str 
 * @param length 
 */
__attribute__((__unused__))
static errval_t handle_terminal_print(const char* str, size_t length)
{
	// TODO: this should be moved to the serial driver when it is written
	errval_t err = sys_print(str, length);
	
	if (err_is_fail(err)) {
		USER_PANIC_ERR(err, "unable to print to terminal!");
		return err;
	}
	
	return SYS_ERR_OK;
}



__attribute__((unused))
static errval_t rpc_reply(void *rpc, struct capref cap, void *buf, size_t size) {
    struct lmp_chan *lc = rpc;
    errval_t err;
    uintptr_t words[LMP_MSG_LENGTH];
    struct capref send_cap;
    err = rpc_marshall(STR_MSG, cap, buf, size, words, &send_cap); 

    if(err_is_fail(err))
        return err_push(err, LIB_ERR_MARSHALL_FAIL);

    //send or die
    while(true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, cap, words[0], words[1], words[2], words[3]);

        if(lmp_err_is_transient(err))
            thread_yield(); //TODO : ensure validity
        else
            break;
    }

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "LMP Sending failed!!!");
        return err;
    }

    return SYS_ERR_OK;
}

//size is unreliable for non-fixed size messages.
__attribute__((unused))
static errval_t handle_general_recv(void *rpc, enum msg_type identifier, struct capref cap, void *buf, size_t size) {
    errval_t err;
    //we have a frame cap, map into our space and set buf to mapped address
    if(!capref_is_null(cap)) {
        void *buffer;
        err = paging_map_frame(get_current_paging_state(), &buffer, size, cap);
        if(err_is_fail(err))
            return err_push(err, LIB_ERR_PAGING_MAP);
        buf = buffer;
    }
    //TODO FILL IN CALLS TO NECESSARY FUNCTIONS HERE
    //Protocol : words[0][2:0] has the type, words[1] has the size IFF it is an STR_MSG.
    switch(identifier) {
    case NUM_MSG:
        break;
    case STR_MSG:
        break;
    case RAM_MSG:
        break;
    case SPAWN_MSG:
        break;
    case TERMINAL_MSG:
		{
			// don't care about capabilities for now
			char *info;
			info = buf;
			if (info[0] == 0) { // putchar
				// no response necessary here
				return sys_print(info+1, 1); // print a single char
			} else if (info[0] == 1) { // getchar
				char c;
				err = sys_getchar(&c + 1);
				// TODO: handle error
				
				info[1] = c; // set the response value
				return rpc_reply(rpc, NULL_CAP, info, 2); // return the requested character
			}
		}
        break;
    }

    return SYS_ERR_OK;
}

//Register this function after spawning a process to register a receive handler to that child process
static void rpc_recv_handler(void *arg)
{
    struct lmp_chan *lc = arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    errval_t err;

    // Try to receive a message
    err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err)) {
        if (lmp_err_is_transient(err)) {
            // Re-register
            err = lmp_chan_register_recv(lc, get_default_waitset(),
                                         MKCLOSURE(rpc_recv_handler, arg));
            if (err_is_ok(err)) return;  // otherwise, fall through
        }
        USER_PANIC_ERR(err_push(err, LIB_ERR_BIND_INIT_SET_RECV),
                       "unhandled error in init_ack_handler");
    }

    char *buf = (char *) msg.words;
    enum msg_type type;
    memcpy(&type, buf, MSG_TYPE_SIZE);
    buf += MSG_TYPE_SIZE;
    size_t size = msg.buf.msglen - MSG_TYPE_SIZE;
    
    if(type == STR_MSG) {
        memcpy(&size, buf, sizeof(size_t));
        buf += sizeof(size_t);
    }

    err = handle_general_recv(arg, type, cap, (void *)buf, size);

    if(err_is_fail(err))
       USER_PANIC_ERR(err_push(err, LIB_ERR_RPC_HANDLE), "error handling message");

    err = lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(rpc_recv_handler, arg));
    if(err_is_fail(err))
        USER_PANIC_ERR(err_push(err, LIB_ERR_BIND_INIT_SET_RECV), "error re-registering handler");
}

static int
bsp_main(int argc, char *argv[]) {
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if(err_is_fail(err)){
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

    spawn_set_rpc_handler(rpc_recv_handler);

    // TODO: initialize mem allocator, vspace management here

    // Grading
    grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here

    // Grading
    grading_test_late();

    debug_printf("Message handler loop\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}

static int
app_main(int argc, char *argv[]) {
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    return LIB_ERR_NOT_IMPLEMENTED;
}



int main(int argc, char *argv[])
{
    errval_t err;


    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    assert(err_is_ok(err));
    disp_set_core_id(my_core_id);

    debug_printf("init: on core %" PRIuCOREID ", invoked as:", my_core_id);
    for (int i = 0; i < argc; i++) {
       printf(" %s", argv[i]);
    }
    printf("\n");
    fflush(stdout);


    if(my_core_id == 0) return bsp_main(argc, argv);
    else                return app_main(argc, argv);
}
