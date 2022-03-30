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




struct bootinfo *bi;

coreid_t my_core_id;

static void rpc_reply(void *rpc, struct capref cap, void *buf, size_t size) {
    lmp_chan_send();
}

__attribute__((unused))
static void handle_general_recv(void *rpc, uintptr_t identifier, struct capref cap, void *buf, size_t size) {
    //TODO FILL IN CALLS TO NECESSARY FUNCTIONS HERE
    //Protocol : words[0] has the type, words[1] has the size, and words[2],words[3] contain the rest of the data IFF cap is NULL, otherwise the cap contains everything
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
        rpc_reply(rpc, ...);
        break;
    }
}

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
                                         MKCLOSURE(init_ack_handler, arg));
            if (err_is_ok(err)) return;  // otherwise, fall through
        }
        USER_PANIC_ERR(err_push(err, LIB_ERR_BIND_INIT_SET_RECV),
                       "unhandled error in init_ack_handler");
    }

    assert(capcmp(lc->remote_cap, cap_initep));  // should be the original one
    lc->remote_cap = cap;
    lc->connstate = LMP_CONNECTED;
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
