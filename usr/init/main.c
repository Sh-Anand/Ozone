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
#include <aos/coreboot.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/kernel_cap_invocations.h>
#include <mm/mm.h>
#include <grading.h>
#include <aos/capabilities.h>
#include <ringbuffer/ringbuffer.h>

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
__attribute__((__unused__)) static errval_t handle_terminal_print(const char *str,
                                                                  size_t length)
{
    // TODO: this should be moved to the serial driver when it is written
    errval_t err = sys_print(str, length);

    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "unable to print to terminal!");
        return err;
    }

    return SYS_ERR_OK;
}


static void rpc_send(void *rpc, uint8_t identifier, struct capref cap, void *buf,
                     size_t size)
{
    struct lmp_chan *lc = rpc;
    errval_t err;
    uintptr_t words[LMP_MSG_LENGTH];

    struct capref send_cap;
    err = rpc_marshall(identifier, cap, buf, size, words, &send_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err_push(err, LIB_ERR_MARSHALL_FAIL), "rpc_reply: marshall failed");
        // XXX: maybe kill the caller here
        return;
    }

    // Send or die
    while (true) {
        err = lmp_chan_send4(lc, LMP_SEND_FLAGS_DEFAULT, cap, words[0], words[1],
                             words[2], words[3]);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                thread_yield();
            } else {
                DEBUG_ERR(err, "rpc_reply: send failed");
                // XXX: maybe kill the caller here
                return;
            }
        } else {
            break;
        }
    }
}

static void rpc_reply(void *rpc, struct capref cap, void *buf, size_t size)
{
    rpc_send(rpc, RPC_ACK_MSG, cap, buf, size);
}

static void rpc_nack(void *rpc, errval_t err)
{
    rpc_send(rpc, RPC_ERR_MSG, NULL_CAP, &err, sizeof(errval_t));
}

/**
 * Dispatching handler for RPC.
 * @param rpc
 * @param identifier
 * @param cap
 * @param buf
 * @param size
 * @return Either call rpc_reply() and return SYS_ERR_OK, or return an error without
 *         calling rpc_reply(), which will be automatically replied to the caller.
 */
static errval_t handle_general_recv(void *rpc, enum msg_type identifier,
                                    struct capref cap, void *buf, size_t size)
{
    errval_t err;

    // TODO: no, this prevent us from receving cap
    // we have a frame cap, map into our space and set buf to mapped address
    if (!capref_is_null(cap)) {
        void *buffer;
        DEBUG_PRINTF("Trying to map received frame in local space\n");
        err = paging_map_frame(get_current_paging_state(), &buffer,
                               ROUND_UP(size, BASE_PAGE_SIZE), cap);
        if (err_is_fail(err))
            return err_push(err, LIB_ERR_PAGING_MAP);
        buf = buffer;
    }

    switch (identifier) {
    case NUM_MSG: {
        uintptr_t num = *((uintptr_t *)buf);
        grading_rpc_handle_number(num);
        debug_printf("Received number %lu in init\n", num);
        rpc_reply(rpc, NULL_CAP, NULL, 0);
    } break;
    case STR_MSG: {
        char *msg = (char *)buf;
        grading_rpc_handler_string(msg);
        debug_printf("Received string in init: \"%s\"\n", msg);
        rpc_reply(rpc, NULL_CAP, NULL, 0);
    } break;
    case RAM_MSG: {
        struct aos_rpc_msg_ram ram_msg = *(struct aos_rpc_msg_ram *)buf;
        struct capref ram;
        grading_rpc_handler_ram_cap(ram_msg.size, ram_msg.alignment);
        err = aos_ram_alloc_aligned(&ram, ram_msg.size, ram_msg.alignment);
        if (err_is_fail(err)) {
            return err;
        }
        rpc_reply(rpc, ram, NULL, 0);
    } break;
    case RPC_PROCESS_SPAWN_MSG: {
        struct rpc_process_spawn_call_msg *msg = buf;
        grading_rpc_handler_process_spawn(msg->cmdline, msg->core);

        struct spawninfo info;
        domainid_t pid;
        err = spawn_load_cmdline(msg->cmdline, &info, &pid);
        if (err_is_fail(err)) {
            return err;
        }

        struct rpc_process_spawn_return_msg reply = { .pid = pid };
        rpc_reply(rpc, NULL_CAP, &reply, sizeof(reply));
    } break;
    case RPC_PROCESS_GET_NAME_MSG: {
        struct rpc_process_get_name_call_msg *msg = buf;
        grading_rpc_handler_process_get_name(msg->pid);

        char *name = NULL;
        err = spawn_get_name(msg->pid, &name);
        if (err_is_fail(err)) {
            return err;
        }

        // XXX: bypass rpc_process_get_name_return_msg
        rpc_reply(rpc, NULL_CAP, name, strlen(name) + 1);

        free(name);
    } break;
    case RPC_PROCESS_GET_ALL_PIDS_MSG: {
        grading_rpc_handler_process_get_all_pids();

        size_t count;
        domainid_t *pids;
        err = spawn_get_all_pids(&pids, &count);
        if (err_is_fail(err)) {
            return err;
        }

        size_t reply_size = sizeof(struct rpc_process_get_all_pids_return_msg)
                            + count * sizeof(domainid_t);
        struct rpc_process_get_all_pids_return_msg *reply = malloc(reply_size);
        if (reply == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        reply->count = count;
        memcpy(reply->pids, pids, count * sizeof(domainid_t));
        free(pids);
        rpc_reply(rpc, NULL_CAP, reply, reply_size);
        free(reply);
    } break;
    case TERMINAL_MSG: {
        // don't care about capabilities for now
        char *info = buf;
        if (info[0] == 0) {  // putchar
            grading_rpc_handler_serial_putchar(info[1]);
            // no response necessary here
            err = sys_print(info + 1, 1);  // print a single char
            if (err_is_fail(err)) {
                return err;
            }
            rpc_reply(rpc, NULL_CAP, NULL, 0);
        } else if (info[0] == 1) {  // getchar
            char c;
            grading_rpc_handler_serial_getchar();
            err = sys_getchar(&c);
            if (err_is_fail(err)) {
                return err;
            }
            info[1] = c;                        // set the response value
            rpc_reply(rpc, NULL_CAP, info, 2);  // return the requested character
        }
    } break;
    default:
        DEBUG_PRINTF("Unexpected message identifier %d\n", identifier);
    }

    return SYS_ERR_OK;
}

static errval_t boot_core(coreid_t mpid) {
    errval_t err;

    struct capref urpc_frame;
    err = frame_alloc(&urpc_frame, URPC_FRAME_SIZE, NULL); //TODO: REPLACE WITH A FIXED UMP FRAME SIZE LATER!

    if(err_is_fail(err))
        return err;

    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    if(err_is_fail(err))
        return err;
    
    void *urpc_buffer;
    err = paging_map_frame(get_current_paging_state(), &urpc_buffer, URPC_FRAME_SIZE, urpc_frame);
    if(err_is_fail(err))
        return err;
    
    //INIT ring buffer
    err = ring_init(urpc_buffer);
    if(err_is_fail(err))
        return err;
    
    //INIT URPC PRODUCER
    struct ring_producer *urpc_sender = malloc(sizeof(struct ring_producer));
    err = ring_producer_init(urpc_sender, urpc_buffer);
    if(err_is_fail(err))
        return err;
    
    //CHANGE cpu_a57_qemu to cpu_imx8x when using the board
    err = coreboot(mpid, "boot_armv8_generic", "cpu_a57_qemu", "init", urpc_frame_id);

    if(err_is_fail(err))
        return err;

    DEBUG_PRINTF("CORE %d SUCCESSFULLY BOOTED\n", mpid);

    // generate a new bootinfo for the child core
    // first allocate some memory for the child
    struct capref core_ram;
    err = ram_alloc(&core_ram, RAM_PER_CORE);
    if(err_is_fail(err))
        return err;

    struct capability c;
    err = cap_direct_identify(core_ram, &c);
    if(err_is_fail(err))
        return err;
    struct mem_region region;
    region.mr_base = c.u.ram.base;
    region.mr_bytes = c.u.ram.bytes;
    region.mr_consumed = false;
    region.mr_type = RegionType_Empty;

    size_t size_buf = sizeof(struct bootinfo) + (bi->regions_length + 1)*sizeof(struct mem_region);
    struct bootinfo *bi_core = malloc(size_buf);
    bi_core->host_msg = bi->host_msg;
    bi_core->host_msg_bits = bi->host_msg_bits;
    bi_core->mem_spawn_core = bi->mem_spawn_core;
    bi_core->regions_length = bi->regions_length + 1;

    memcpy(bi_core->regions, bi->regions, sizeof(struct mem_region)*bi->regions_length);

    bi_core->regions[bi->regions_length] = region;

    //send bootinfo across
    err = ring_producer_transmit(urpc_sender, bi_core, size_buf);

    DEBUG_PRINTF("BSP BOOTINFO HAS %d regions\n", bi->regions_length);
    return SYS_ERR_OK;
}

// Register this function after spawning a process to register a receive handler to that
// child process
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
            if (err_is_ok(err))
                return;  // otherwise, fall through
        }
        DEBUG_ERR(err, "rpc_recv_handler: unhandled error from lmp_chan_recv");
        // XXX: maybe kill the caller here
    }

    // Refill the cap slot
    if (!capref_is_null(cap)) {
        struct capref new_slot;
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_recv_handler: fail to alloc new slot");
            // XXX: maybe kill the caller here
        }
        lmp_chan_set_recv_slot(lc, new_slot);
    }

    uint8_t *buf = (uint8_t *)msg.words;
    uint8_t type = buf[0];
    buf += 1;
    size_t size = msg.buf.msglen - MSG_TYPE_SIZE;

    err = handle_general_recv(arg, type, cap, (void *)buf, size);
    if (err_is_fail(err)) {
        rpc_nack(lc, err);  // reply error
    }

    // Re-register
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(rpc_recv_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "rpc_recv_handler: error re-registering handler");
        // XXX: maybe kill the caller here
    }
}

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

    spawn_set_rpc_handler(rpc_recv_handler);

    // TODO: initialize mem allocator, vspace management here

    // Grading
    //grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here
    
    //Booting second core
    err = boot_core(1);
    if(err_is_fail(err))
        DEBUG_ERR(err, "failed to boot second core");
    
    // Grading
    //grading_test_late();

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

// Call with the appropriately prepared bootinfo struct with the allocated RAM in the last location of the memregs array
static errval_t forge_ram(struct bootinfo *bootinfo) {
    errval_t err; 
    
    //It is guaranteed that the last region in the bootinfo is the RAM we need. Forge it now
    struct mem_region region = bootinfo->regions[bootinfo->regions_length-1];
    
    //Sanity checks
    assert(region.mr_type == RegionType_Empty);

    //As seen from the init ram alloc function in mem_alloc.c, we place the RAM cap in the first slot of cnode_super
    struct capref ram = {
        .cnode = cnode_super,
        .slot = 0
    };

    //Finally, forge
    err = ram_forge(ram, region.mr_base, region.mr_bytes, disp_get_current_core_id());

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to forge RAM");
        return err;
    }

    return SYS_ERR_OK;
}

// // Forge caps to all the modules in the memregs structure
// static errval_t forge_modules(struct bootinfo *bi) {
    
// }

static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();

    errval_t err;

    // map URPC frame to our addr
    void *urpc_addr;
    err = paging_map_frame(get_current_paging_state(), &urpc_addr, URPC_FRAME_SIZE, cap_urpc);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main mapping URPC frame");
        abort();
    }

    // init ring buffer consumer
    struct ring_consumer urpc_recv;
    err = ring_consumer_init(&urpc_recv, urpc_addr);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main init URPC receiver");
        abort();
    }

    // create bootinfo 
    size_t bi_size;
    err = ring_consumer_recv(&urpc_recv, (void **)&bi, &bi_size);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get bootinfo from BSP core");
        abort();
    }
    
    // forge the received RAM
    err = forge_ram(bi);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge ram in app main");
        abort();
    }

    grading_setup_app_init(bi);

    // initialize ram allocator
    err = initialize_ram_alloc();
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to initialize ram allocator");
        abort();
    }

    spawn_set_rpc_handler(rpc_recv_handler);

    // grading_test_early();

    // grading_test_late();

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


    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
