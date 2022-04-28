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
#include <barrelfish_kpi/platform.h>
#include <spawn/spawn.h>
#include "rpc_handlers.h"

struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

struct ring_producer *urpc_send = NULL;  // currently only for core 0 and 1
struct ring_consumer *urpc_recv = NULL;  // currently only for core 0 and 1
struct thread *urpc_recv_thread = NULL;  // currently only for core 1

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

static errval_t boot_core(coreid_t mpid)
{
    errval_t err;

    struct capref urpc_frame;
    err = frame_alloc(&urpc_frame, URPC_FRAME_SIZE,
                      NULL);  // TODO: REPLACE WITH A FIXED UMP FRAME SIZE LATER!

    if (err_is_fail(err)) {
        return err;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    if (err_is_fail(err)) {
        return err;
    }

    uint8_t *urpc_buffer;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_buffer, URPC_FRAME_SIZE,
                           urpc_frame);
    if (err_is_fail(err)) {
        return err;
    }

    // INIT ring buffer
    err = ring_init(urpc_buffer);
    if (err_is_fail(err))
        return err;
    err = ring_init(urpc_buffer + BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    // INIT URPC PRODUCER
    urpc_send = malloc(sizeof(struct ring_producer));
    if (urpc_send == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = ring_producer_init(urpc_send, urpc_buffer);
    if (err_is_fail(err)) {
        return err;
    }

    urpc_recv = malloc(sizeof(struct ring_consumer));
    if (urpc_recv == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = ring_consumer_init(urpc_recv, urpc_buffer + BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    // CHANGE cpu_a57_qemu to cpu_imx8x when using the board
    err = coreboot(mpid, "boot_armv8_generic", "cpu_a57_qemu", "init", urpc_frame_id);

    if (err_is_fail(err))
        return err;

    DEBUG_PRINTF("CORE %d SUCCESSFULLY BOOTED\n", mpid);

    // generate a new bootinfo for the child core
    // first allocate some memory for the child
    struct capref core_ram;
    err = ram_alloc(&core_ram, RAM_PER_CORE);
    if (err_is_fail(err))
        return err;

    struct capability c;
    err = cap_direct_identify(core_ram, &c);
    if (err_is_fail(err))
        return err;
    struct mem_region region;
    region.mr_base = c.u.ram.base;
    region.mr_bytes = c.u.ram.bytes;
    region.mr_consumed = false;
    region.mr_type = RegionType_Empty;

    size_t size_buf = sizeof(struct bootinfo)
                      + (bi->regions_length + 1) * sizeof(struct mem_region);
    struct bootinfo *bi_core = malloc(size_buf);
    bi_core->host_msg = bi->host_msg;
    bi_core->host_msg_bits = bi->host_msg_bits;
    bi_core->mem_spawn_core = bi->mem_spawn_core;
    bi_core->regions_length = bi->regions_length + 1;

    memcpy(bi_core->regions, bi->regions, sizeof(struct mem_region) * bi->regions_length);

    bi_core->regions[bi->regions_length] = region;

    // send bootinfo across
    err = ring_producer_transmit(urpc_send, bi_core, size_buf);
    if(err_is_fail(err))
        return err;
    
    // send mm_strings cap across
    struct frame_identity mm_strings_id;
    err = frame_identify(cap_mmstrings, &mm_strings_id);
    if(err_is_fail(err))
        return err;
    
    err = ring_producer_transmit(urpc_send, &mm_strings_id, sizeof(struct frame_identity));
    if(err_is_fail(err))
        return err;

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
            // FIXME: what?
        }
        DEBUG_ERR(err, "rpc_recv_handler: unhandled error from lmp_chan_recv");
        // XXX: maybe kill the caller here
    }

    // Refill the cap slot if the recv slot is used (received a cap)
    if (!capref_is_null(cap)) {
        struct capref new_slot = NULL_CAP;
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_recv_handler: fail to alloc new slot");
            // XXX: maybe kill the caller here
            goto RE_REGISTER;
        }
        assert(!capref_is_null(new_slot));
        lmp_chan_set_recv_slot(lc, new_slot);
    }

    uint8_t *buf = (uint8_t *)msg.words;
    uint8_t type = buf[0];
    if (type >= RPC_MSG_COUNT) {
        DEBUG_PRINTF("Invalid RPC msg %u\n", type);
        rpc_nack(lc, LIB_ERR_RPC_INVALID_MSG);
        goto RE_REGISTER;
    }
    buf += 1;
    size_t size = msg.buf.msglen * (sizeof(uintptr_t)) - 1;

    // we have a frame cap, map into our space and set buf to mapped address
    // TODO: now cap is only for frame-based message, which prevent us from receving cap
    if (!capref_is_null(cap)) {
        DEBUG_PRINTF("Trying to map received frame in local space\n");
        err = paging_map_frame(get_current_paging_state(), (void **)&buf,
                               ROUND_UP(size, BASE_PAGE_SIZE), cap);
        if (err_is_fail(err)) {
            rpc_nack(lc, err_push(err, LIB_ERR_PAGING_MAP));
            goto RE_REGISTER;
        }
        size = BASE_PAGE_SIZE;
    }

    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    err = rpc_handlers[type](buf, size, &reply_payload, &reply_size, &reply_cap);
    if (err_is_ok(err)) {
        rpc_reply(lc, reply_cap, reply_payload, reply_size);
    } else {
        rpc_nack(lc, err);  // reply error
    }

    // Clean up, regardless of err is ok or fail
    if (reply_payload != NULL) {
        free(reply_payload);
    }


RE_REGISTER:
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
    grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here

    // Booting second core
    err = boot_core(1);
    if (err_is_fail(err))
        DEBUG_ERR(err, "failed to boot second core");

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

// Call with the appropriately prepared bootinfo struct with the allocated RAM in the last
// location of the memregs array
static errval_t forge_ram(struct bootinfo *bootinfo)
{
    errval_t err;

    // It is guaranteed that the last region in the bootinfo is the RAM we need. Forge it now
    struct mem_region region = bootinfo->regions[bootinfo->regions_length - 1];

    // Sanity checks
    assert(region.mr_type == RegionType_Empty);

    // As seen from the init ram alloc function in mem_alloc.c, we place the RAM cap in
    // the first slot of cnode_super
    struct capref ram = { .cnode = cnode_super, .slot = 0 };

    // Finally, forge
    err = ram_forge(ram, region.mr_base, region.mr_bytes, disp_get_current_core_id());

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to forge RAM");
        return err;
    }

    return SYS_ERR_OK;
}

// // Forge caps to all the modules in the memregs structure
static errval_t forge_modules(struct bootinfo *bootinfo) {
    errval_t err;

    //create an L2 node into the ROOTCN_SLOT_MODULECN
    struct cnoderef modulecn_ref;
    err = cnode_create_foreign_l2(cap_root, ROOTCN_SLOT_MODULECN, &modulecn_ref);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to create L2 node for cnode_module");
        return err;
    }
    assert(cnodecmp(modulecn_ref, cnode_module));

    for(int i=0; i < bootinfo->regions_length; i++) {
        if(bootinfo->regions[i].mr_type == RegionType_Module) {
            struct capref module = {
                .cnode = cnode_module,
                .slot = bootinfo->regions[i].mrmod_slot
            };
            DEBUG_PRINTF("slot = %u\n", bootinfo->regions[i].mrmod_slot);
            err = frame_forge(module, bootinfo->regions[i].mr_base, bootinfo->regions[i].mr_bytes, disp_get_core_id());
            if(err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to forge frame for module in region %d", i);
                return err;
            }
        }
    }

    return SYS_ERR_OK;
}

static int urpc_server_worker(void *params)
{
    uint8_t *recv_payload;
    size_t recv_size;
    while (true) {
        errval_t err = ring_consumer_recv(urpc_recv, (void **)&recv_payload, &recv_size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ring_consumer_recv failed\n");
            return EXIT_FAILURE;
        }

        uint8_t type = recv_payload[0];
        if (type >= RPC_MSG_COUNT) {
            DEBUG_PRINTF("Invalid URPC msg %u\n", type);
            continue;
        }

        void *reply_payload = NULL;
        size_t reply_size = 0;
        struct capref reply_cap = NULL_CAP;
        err = rpc_handlers[type](recv_payload + 1, recv_size - 1, &reply_payload, &reply_size, &reply_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in rpc handler %u\n", type);
        }

        // FIXME: reply is discarded for now
    }
    return EXIT_SUCCESS;
}


static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();

    errval_t err;

    // map URPC frame to our addr
    uint8_t *urpc_addr;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_addr, URPC_FRAME_SIZE,
                           cap_urpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main mapping URPC frame");
        abort();
    }

    // init ring buffer consumer
    urpc_recv = malloc(sizeof(struct ring_consumer));
    if (urpc_recv == NULL) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to malloc ring_consumer");
        abort();
    }
    err = ring_consumer_init(urpc_recv, urpc_addr);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main init URPC receiver");
        abort();
    }

    urpc_send = malloc(sizeof(struct ring_producer));
    if (urpc_send == NULL) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to malloc ring_producer");
        abort();
    }
    err = ring_producer_init(urpc_send, urpc_addr + BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main init URPC sender");
        abort();
    }

    // create bootinfo
    size_t bi_size;
    err = ring_consumer_recv(urpc_recv, (void **)&bi, &bi_size);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get bootinfo from BSP core");
        abort();
    }

    // forge the received RAM
    err = forge_ram(bi);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge ram in app main");
        abort();
    }

    grading_setup_app_init(bi);

    // initialize ram allocator
    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to initialize ram allocator");
        abort();
    }

    // forge modules and set the MODULECN cnode
    err = forge_modules(bi);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge modules");
        abort();
    }

    // get cap_mmstrings
    struct frame_identity *mm_strings_id;
    size_t frameid_size;
    err = ring_consumer_recv(urpc_recv, (void **)&mm_strings_id, &frameid_size);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get mmstrings cap");
        abort();
    }
    err = frame_forge(cap_mmstrings, mm_strings_id->base, mm_strings_id->bytes, disp_get_current_core_id());
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge cap_mmstrings");
        abort();
    }

    spawn_set_rpc_handler(rpc_recv_handler);

    grading_test_early();

    grading_test_late();

    urpc_recv_thread = thread_create(urpc_server_worker, NULL);
    if (urpc_recv_thread == NULL) {
        DEBUG_ERR(err, "failed to create urpc_recv_thread");
        abort();
    }

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

    /* obtain the core information from the kernel*/
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the core id from the kernel\n");
    }

    /* Set the core id in the disp_priv struct */
    disp_set_core_id(my_core_id);

    /* obtain the platform information */
    err = invoke_kernel_get_platform_info(cap_kernel, &platform_info);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the platform info from the kernel\n");
    }

    char *platform;
    switch (platform_info.platform) {
    case PI_PLATFORM_QEMU:
        platform = "QEMU";
        break;
    case PI_PLATFORM_IMX8X:
        platform = "IMX8X";
        break;
    default:
        platform = "UNKNOWN";
    }

    debug_printf("init domain starting on core %" PRIuCOREID " (%s), invoked as:",
                 my_core_id, platform);
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
