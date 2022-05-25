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
#include <aos/ump_chan.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/lmp_handler_builder.h>
#include <aos/ump_handler_builder.h>
#include <mm/mm.h>
#include <grading.h>
#include <aos/capabilities.h>
#include <ringbuffer/ringbuffer.h>

#include "mem_alloc.h"
#include <barrelfish_kpi/platform.h>
#include <spawn/spawn.h>
#include "init_urpc.h"
#include "rpc_handlers.h"

#include <maps/imx8x_map.h>
#include <maps/qemu_map.h>

struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

struct aos_rpc nameserver_rpc;

struct capref dev_cap_sdhc2;
struct capref dev_cap_enet;

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

static void rpc_lmp_handler(void *arg)
{
    errval_t err;

    struct proc_node *proc = arg;
    struct aos_chan *chan = &proc->chan;
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->lc;

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type, recv_buf,
                                recv_size, helper, RE_REGISTER, FAILURE)

    // If the channel is not setup yet, set it up
    if (lc->connstate == LMP_BIND_WAIT) {
        LMP_TRY_SETUP_BINDING(err, lc, recv_cap, FAILURE)

        // Ack
        err = aos_chan_ack(chan, NULL_CAP, NULL, 0);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_lmp_handler (binding): aos_chan_ack failed\n");
            goto FAILURE;
        }

        // Protocol: payload is the domain ID
        DEBUG_PRINTF("rpc_lmp_handler: bind process %lu\n", recv_raw_msg.words[0]);
        goto RE_REGISTER;
    }

    // Sanity check, LMP can only accept RPC exposed to the user
    if (recv_type >= RPC_MSG_COUNT || rpc_handlers[recv_type] == NULL) {
        DEBUG_PRINTF("rpc_lmp_handler: invalid recv_type %u\n", recv_type);
        aos_chan_nack(chan, LIB_ERR_RPC_INVALID_MSG);
        goto RE_REGISTER;
    }

    // Call the handler
    LMP_DISPATCH_AND_REPLY_MAY_FAIL(err, chan, proc, rpc_handlers[recv_type], recv_cap)

    // Deserialization cleanup
    LMP_CLEANUP(err, helper)

FAILURE:
    // XXX: maybe kill the caller here
RE_REGISTER:
    LMP_RE_REGISTER(err, lc, rpc_lmp_handler, arg)
}

void init_urpc_handler(void *arg)
{
    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->uc;

    errval_t err;

    UMP_RECV_DESERIALIZE(uc)

    // Obviously no init-assisted cap transfer since we are just in init
    UMP_RECV_NO_CAP

    // DEBUG_PRINTF("init_urpc_handler: handling %u\n", type);

    UMP_ASSERT_DISPATCHER(rpc_handlers, INTERNAL_RPC_MSG_COUNT);

    UMP_DISPATCH_AND_REPLY_MAY_FAIL(chan, rpc_handlers[recv_type], NULL)

    UMP_CLEANUP_AND_RE_REGISTER(uc, init_urpc_handler, arg)
}

static errval_t boot_core(coreid_t core)
{
    errval_t err;

    struct capref urpc_frame;
    err = frame_alloc(&urpc_frame, INIT_BIDIRECTIONAL_URPC_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    if (err_is_fail(err)) {
        return err;
    }

    // BSP core is responsible for zeroing the URPC frame
    // Existing core: listener first
    err = setup_urpc(core, urpc_frame, true, true);
    if (err_is_fail(err)) {
        return err;
    }

    // Choose the right bootloader and cpu driver image

    err = invoke_kernel_get_platform_info(cap_kernel, &platform_info);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the platform info from the kernel\n");
    }

    char *bootloader_image;
    switch (platform_info.arch) {
    case PI_ARCH_ARMV8A:
        bootloader_image = "boot_armv8_generic";
        break;
    default:
        USER_PANIC("unsupported arch %d\n", platform_info.arch);
    }

    char *cpu_driver_image;
    switch (platform_info.platform) {
    case PI_PLATFORM_QEMU:
        cpu_driver_image = "cpu_a57_qemu";
        break;
    case PI_PLATFORM_IMX8X:
        cpu_driver_image = "cpu_imx8x";
        break;
    default:
        USER_PANIC("unknown platform %d\n", platform_info.platform);
    }

    err = coreboot(core, bootloader_image, cpu_driver_image, "init", urpc_frame_id);

    if (err_is_fail(err)) {
        return err;
    }

    DEBUG_PRINTF("CORE %d SUCCESSFULLY BOOTED\n", core);

    // generate a new bootinfo for the child core
    // first allocate some memory for the child
    struct capref core_ram;
    err = ram_alloc(&core_ram, RAM_PER_CORE);
    if (err_is_fail(err)) {
        return err;
    }

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

    // send bootinfo across, by passing aos_rpc and aos_chan
    err = ring_producer_send(&urpc_listen_from[core]->uc.send, bi_core, size_buf);
    if (err_is_fail(err)) {
        return err;
    }

    // send mm_strings cap across
    struct frame_identity mm_strings_id;
    err = frame_identify(cap_mmstrings, &mm_strings_id);
    if (err_is_fail(err)) {
        return err;
    }
    err = ring_producer_send(&urpc_listen_from[core]->uc.send, &mm_strings_id,
                             sizeof(struct frame_identity));
    if (err_is_fail(err)) {
        return err;
    }

    // Start handling URPCs from the newly booted core
    err = ump_chan_register_recv(&urpc_listen_from[core]->uc, get_default_waitset(),
                                 MKCLOSURE(init_urpc_handler, urpc_listen_from[core]));
    if (err_is_fail(err)) {
        return err;
    }

    // Help setup URPC with existing cores
    for (coreid_t i = 1; i < MAX_COREID; i++) {
        if (i != core && urpc[i] != NULL) {  // another booted core

            DEBUG_PRINTF("coordinate URPC setup between core %u and %u\n", core, i);

            err = frame_alloc(&urpc_frame, INIT_BIDIRECTIONAL_URPC_FRAME_SIZE, NULL);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_FRAME_ALLOC);
            }

            uint8_t *urpc_buffer;
            err = paging_map_frame(get_current_paging_state(), (void **)&urpc_buffer,
                                   INIT_BIDIRECTIONAL_URPC_FRAME_SIZE, urpc_frame);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_PAGING_MAP);
            }

            // BSP core is responsible for zeroing the URPC frame
            memset(urpc_buffer, 0, INIT_BIDIRECTIONAL_URPC_FRAME_SIZE);

            err = paging_unmap(get_current_paging_state(), (void *)urpc_buffer);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_PAGING_UNMAP);
            }

            struct internal_rpc_bind_core_urpc_msg msg;
            err = frame_identify(urpc_frame, &msg.frame);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_FRAME_IDENTIFY);
            }

            msg.core = core;
            msg.listener_first = true;  // existing core
            err = aos_rpc_call(urpc[i], INTERNAL_RPC_BIND_CORE_URPC, NULL_CAP, &msg,
                               sizeof(msg), NULL, NULL, NULL);
            if (err_is_fail(err)) {
                return err;
            }

            msg.core = i;
            msg.listener_first = false;  // newly booted core
            err = aos_rpc_call(urpc[core], INTERNAL_RPC_BIND_CORE_URPC, NULL_CAP, &msg,
                               sizeof(msg), NULL, NULL, NULL);
            if (err_is_fail(err)) {
                return err;
            }
        }
    }

    return SYS_ERR_OK;
}

static void lmp_one_time_binding_handler(void *arg)
{
    errval_t err;
    struct aos_chan *chan = arg;
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    struct lmp_chan *lc = &chan->lc;

    // Receive the message and cap, refill the recv slot, deserialize
    LMP_RECV_REFILL_DESERIALIZE(err, lc, recv_raw_msg, recv_cap, recv_type, recv_buf,
                                recv_size, helper, DONE, FAILURE)

    // If the channel is not setup yet, set it up
    if (lc->connstate == LMP_BIND_WAIT) {
        LMP_TRY_SETUP_BINDING(err, lc, recv_cap, FAILURE)

        // Ack
        err = aos_chan_ack(chan, NULL_CAP, NULL, 0);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_lmp_handler (binding): aos_chan_ack failed\n");
            goto FAILURE;
        }

        assert(lc->connstate == LMP_CONNECTED);
        DEBUG_PRINTF("nameserver registered\n");
        goto DONE;
    }

    // Deserialization cleanup
    LMP_CLEANUP(err, helper)

FAILURE:
DONE:
    // Do not re-register
    return;
}

static errval_t start_nameserver(void) {
    errval_t err;

    assert(nameserver_rpc.chan.type == AOS_CHAN_TYPE_UNKNOWN);
    err = aos_chan_lmp_init_local(&nameserver_rpc.chan, 32);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_INIT_LOCAL);
    }
    assert(nameserver_rpc.chan.type == AOS_CHAN_TYPE_LMP);

    err = lmp_chan_alloc_recv_slot(&nameserver_rpc.chan.lc);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    assert(nameserver_rpc.chan.lc.connstate == LMP_BIND_WAIT);
    err = lmp_chan_register_recv(&nameserver_rpc.chan.lc, get_default_waitset(), MKCLOSURE(lmp_one_time_binding_handler, &nameserver_rpc.chan));
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CHAN_REGISTER_RECV);
    }

    struct spawninfo si;
    domainid_t pid;
    assert(!capref_is_null(nameserver_rpc.chan.lc.local_cap));
    err = spawn_load_by_name_with_cap("nameserver", nameserver_rpc.chan.lc.local_cap, &si, &pid);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_LOAD);
    }

    return SYS_ERR_OK;
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
        exit(EXIT_FAILURE);
    }

    spawn_init(rpc_lmp_handler);

    // TODO: initialize mem allocator, vspace management here

    // Grading
    grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here
	
	// TODO: TEMPORARY: create device capabilities for non shell projects
	struct capref dev_cap_full = {
		.cnode = { .croot = CPTR_ROOTCN, .cnode = CPTR_TASKCN_BASE, .level = CNODE_TYPE_OTHER },
		.slot = TASKCN_SLOT_DEV
	};
	struct capability dev_cap;
	cap_direct_identify(dev_cap_full, &dev_cap);
	struct capref nullref = { .slot = 0, .cnode = { .cnode = 0, .croot = 0, .level = 0 } };
	char buf[1024];
	
	switch (platform_info.platform) {
	case PI_PLATFORM_IMX8X:
		slot_alloc(&dev_cap_sdhc2);
		cap_retype(dev_cap_sdhc2, dev_cap_full, IMX8X_SDHC2_BASE - dev_cap.u.devframe.base, ObjType_DevFrame, IMX8X_SDHC_SIZE, 1);
		
		debug_print_cap_at_capref(buf, 1023, dev_cap_sdhc2);
		DEBUG_PRINTF("SDHC2 capability: %s\n", buf);
		break;
	default:
		dev_cap_sdhc2 = nullref;
		dev_cap_enet = nullref;
		break;
	}

    // Booting other four cores
    for (int i = 1; i < 4; i++) {
        err = boot_core(i);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to boot core");
        }
    }

    err = start_nameserver();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to start nameserver");
        exit(EXIT_FAILURE);
    }

    // Grading
    grading_test_late();

    debug_printf("Message handler loop\n");

    // Turn off the core
    // uint8_t payload = RPC_SHUTDOWN;
    // err = ring_producer_send(urpc_send, &payload, sizeof(uint8_t));
    // err = psci_cpu_on(1, cpu_driver_entry_point, 0);
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
static errval_t forge_modules(struct bootinfo *bootinfo)
{
    errval_t err;

    // create an L2 node into the ROOTCN_SLOT_MODULECN
    struct cnoderef modulecn_ref;
    err = cnode_create_foreign_l2(cap_root, ROOTCN_SLOT_MODULECN, &modulecn_ref);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed to create L2 node for cnode_module");
        return err;
    }
    assert(cnodecmp(modulecn_ref, cnode_module));

    for (int i = 0; i < bootinfo->regions_length; i++) {
        if (bootinfo->regions[i].mr_type == RegionType_Module) {
            struct capref module = { .cnode = cnode_module,
                                     .slot = bootinfo->regions[i].mrmod_slot };
            err = frame_forge(module, bootinfo->regions[i].mr_base,
                              bootinfo->regions[i].mr_bytes, disp_get_core_id());
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "Failed to forge frame for module in region %d", i);
                return err;
            }
        }
    }

    return SYS_ERR_OK;
}


static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();

    errval_t err;

    // BSP core was responsible for zeroing the URPC frame, see above
    // New core: listener last
    err = setup_urpc(0, cap_urpc, false, false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "fail to setup urpc with core 0");
        abort();
    }

    // create bootinfo
    size_t bi_size;
    err = ring_consumer_recv(&urpc[0]->chan.uc.recv, (void **)&bi, &bi_size);

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
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge modules");
        abort();
    }

    // get cap_mmstrings
    struct frame_identity *mm_strings_id;
    size_t frameid_size;
    err = ring_consumer_recv(&urpc[0]->chan.uc.recv, (void **)&mm_strings_id,
                             &frameid_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get mmstrings cap");
        abort();
    }
    err = frame_forge(cap_mmstrings, mm_strings_id->base, mm_strings_id->bytes,
                      disp_get_current_core_id());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to forge cap_mmstrings");
        abort();
    }

    spawn_init(rpc_lmp_handler);

    grading_test_early();

    grading_test_late();

    // Start handling URPCs from core 0
    assert(urpc_listen_from[0]->type == AOS_CHAN_TYPE_UMP);
    err = ump_chan_register_recv(&urpc_listen_from[0]->uc, get_default_waitset(),
                                 MKCLOSURE(init_urpc_handler, urpc_listen_from[0]));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_chan_register_recv failed");
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
