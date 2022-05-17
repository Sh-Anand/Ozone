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
#include <mm/mm.h>
#include <grading.h>
#include <aos/capabilities.h>
#include <ringbuffer/ringbuffer.h>
#include <drivers/sdhc.h>

#include "mem_alloc.h"
#include <barrelfish_kpi/platform.h>
#include <spawn/spawn.h>
#include "rpc_handlers.h"

#include <maps/imx8x_map.h>
#include <maps/qemu_map.h>

struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

#define URPC_FRAME_SIZE (UMP_CHAN_SHARED_FRAME_SIZE * 2)
struct ump_chan *urpc_server[MAX_COREID] = { NULL };
struct ump_chan *urpc_client[MAX_COREID] = { NULL };

struct capref dev_cap_sdhc2;
struct capref dev_cap_enet;

struct sdhc_s *sd;

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
    rpc_send(rpc, RPC_ACK, cap, buf, size);
}

static void rpc_nack(void *rpc, errval_t err)
{
    rpc_send(rpc, RPC_ERR, NULL_CAP, &err, sizeof(errval_t));
}

// Register this function after spawning a process to register a receive handler to that
// child process
static void rpc_recv_handler(void *arg)
{
    struct lmp_chan *lc = arg;
    struct lmp_recv_msg recv_msg = LMP_RECV_MSG_INIT;
    struct capref recv_cap;
    errval_t err;

    // Try to receive a message
    err = lmp_chan_recv(lc, &recv_msg, &recv_cap);
    if (err_is_fail(err)) {
        if (lmp_err_is_transient(err)) {
            goto RE_REGISTER;
        }
        DEBUG_ERR(err, "rpc_recv_handler: unhandled error from lmp_chan_recv");
        // XXX: maybe kill the caller here
    }

    // Refill the recv_cap slot if the recv slot is used (received a recv_cap)
    if (!capref_is_null(recv_cap)) {
        //        struct capref new_slot = NULL_CAP;
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_recv_handler: fail to alloc new slot");
            // XXX: maybe kill the caller here
            goto RE_REGISTER;
        }
        //        assert(!capref_is_null(new_slot));
        //        lmp_chan_set_recv_slot(lc, new_slot);
    }

    rpc_identifier_t recv_type = *((rpc_identifier_t *)recv_msg.words);

    uint8_t *recv_buf;
    size_t recv_size;

    uint8_t *frame_payload = NULL;

    if (recv_type == RPC_MSG_IN_FRAME) {
        assert(!capref_is_null(recv_cap));

        DEBUG_PRINTF("rpc_recv_handler: trying to map received frame in local space\n");

        struct frame_identity frame_id;
        err = frame_identify(recv_cap, &frame_id);
        if (err_is_fail(err)) {
            rpc_nack(lc, err_push(err, LIB_ERR_FRAME_IDENTIFY));
            goto RE_REGISTER;
        }

        err = paging_map_frame(get_current_paging_state(), (void **)&frame_payload,
                               frame_id.bytes, recv_cap);
        if (err_is_fail(err)) {
            rpc_nack(lc, err_push(err, LIB_ERR_PAGING_MAP));
            goto RE_REGISTER;
        }

        recv_size = *((size_t *)frame_payload);
        recv_type = *((rpc_identifier_t *)(frame_payload + sizeof(size_t)));
        recv_buf = frame_payload + sizeof(size_t) + sizeof(rpc_identifier_t);

    } else if (rpc_handlers[recv_type] == NULL) {
        DEBUG_PRINTF("rpc_recv_handler: invalid recv_type %u\n", recv_type);
        rpc_nack(lc, LIB_ERR_RPC_INVALID_MSG);
        goto RE_REGISTER;

    } else {
        recv_buf = ((uint8_t *)recv_msg.words) + sizeof(rpc_identifier_t);
        recv_size = recv_msg.buf.msglen * (sizeof(uintptr_t)) - sizeof(rpc_identifier_t);
    }

    // DEBUG_PRINTF("rpc_recv_handler: handling %u\n", recv_type);

    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    err = rpc_handlers[recv_type](recv_buf, recv_size, &reply_payload, &reply_size,
                                  &reply_cap);
    if (err_is_ok(err)) {
        rpc_reply(lc, reply_cap, reply_payload, reply_size);
    } else {
        rpc_nack(lc, err);  // reply error
    }

    // Clean up, regardless of err is ok or fail
    if (reply_payload != NULL) {
        free(reply_payload);
    }

    if (frame_payload != NULL) {
        err = paging_unmap(get_current_paging_state(), frame_payload);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "rpc_recv_handler: failed to unmap");
        }
    }


RE_REGISTER:
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(rpc_recv_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "rpc_recv_handler: error re-registering handler");
        // XXX: maybe kill the caller here
    }
}

static void urpc_handler(void *arg)
{
    struct ump_chan *uc = arg;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;

    errval_t err = ump_chan_recv(uc, (void **)&recv_payload, &recv_size);
    if (err == LIB_ERR_RING_NO_MSG) {
        goto RE_REGISTER;
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "urpc_handler: ring_consumer_recv failed\n");
        goto RE_REGISTER;
    }

    uint8_t type = recv_payload[0];
    if (rpc_handlers[type] == NULL) {
        DEBUG_PRINTF("urpc_handler: invalid URPC msg %u\n", type);
        goto FREE_RECV_PAYLOAD;
    }

    // DEBUG_PRINTF("urpc_handler: handling %u\n", type);

    void *reply_payload = NULL;
    size_t reply_size = 0;
    struct capref reply_cap = NULL_CAP;
    err = rpc_handlers[type](recv_payload + 1, recv_size - 1, &reply_payload, &reply_size,
                             &reply_cap);

    uint8_t *reply_buf = NULL;

    if (err_is_fail(err)) {
        reply_buf = malloc(sizeof(rpc_identifier_t) + sizeof(errval_t));
        if (reply_buf == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "urpc_handler: failed to malloc reply_buf");
            goto FREE_REPLY_PAYLOAD;
        }
        *((rpc_identifier_t *)reply_buf) = RPC_ERR;
        *((errval_t *)(reply_buf + sizeof(rpc_identifier_t))) = err;
        reply_size = sizeof(errval_t);
    } else {
        reply_buf = malloc(sizeof(rpc_identifier_t) + reply_size);
        if (reply_buf == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "urpc_handler: failed to malloc reply_buf");
            goto FREE_REPLY_PAYLOAD;
        }
        *((rpc_identifier_t *)reply_buf) = RPC_ACK;
        if (reply_size != 0) {
            memcpy(reply_buf + sizeof(rpc_identifier_t), reply_payload, reply_size);
        }
    }

    err = ump_chan_send(uc, reply_buf, sizeof(rpc_identifier_t) + reply_size);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "urpc_handler: failed to reply URPC\n");
        goto FREE_REPLY_BUF;
    }

FREE_REPLY_BUF:
    free(reply_buf);
FREE_REPLY_PAYLOAD:
    free(reply_payload);
FREE_RECV_PAYLOAD:
    free(recv_payload);
RE_REGISTER:
    err = ump_chan_register_recv(uc, get_default_waitset(), MKCLOSURE(urpc_handler, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "urpc_handler: error re-registering handler");
        // XXX: maybe kill the caller here
    }
}

static errval_t boot_core(coreid_t mpid)
{
    errval_t err;

    struct capref urpc_frame;
    err = frame_alloc(&urpc_frame, URPC_FRAME_SIZE, NULL);

    if (err_is_fail(err)) {
        return err;
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(urpc_frame, &urpc_frame_id);
    if (err_is_fail(err)) {
        return err;
    }

    uint8_t *urpc_buffer;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_buffer,
                           URPC_FRAME_SIZE, urpc_frame);
    if (err_is_fail(err)) {
        return err;
    }

    // BSP core is responsible for zeroing the URPC frame
    memset(urpc_buffer, 0, URPC_FRAME_SIZE);

    // Init URPC server
    urpc_server[mpid] = malloc(sizeof(**urpc_server));
    if (urpc_server[mpid] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = ump_chan_init_from_buf(urpc_server[mpid], urpc_buffer, false);
    if (err_is_fail(err)) {
        return err;
    }

    // Init UPRC client
    urpc_client[mpid] = malloc(sizeof(**urpc_client));
    if (urpc_client[mpid] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = ump_chan_init_from_buf(urpc_client[mpid],
                                 urpc_buffer + UMP_CHAN_SHARED_FRAME_SIZE, true);
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

    err = coreboot(mpid, bootloader_image, cpu_driver_image, "init", urpc_frame_id);

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
    err = ring_producer_send(&urpc_server[mpid]->send, bi_core, size_buf);
    if (err_is_fail(err)) {
        return err;
    }

    // send mm_strings cap across
    struct frame_identity mm_strings_id;
    err = frame_identify(cap_mmstrings, &mm_strings_id);
    if (err_is_fail(err))
        return err;

    err = ring_producer_send(&urpc_server[mpid]->send, &mm_strings_id,
                             sizeof(struct frame_identity));
    if (err_is_fail(err)) {
        return err;
    }

    // Start handling URPCs from the newly booted core
    err = ump_chan_register_recv(urpc_server[mpid], get_default_waitset(),
                                 MKCLOSURE(urpc_handler, urpc_server[mpid]));
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

// initialize sd card: map sd devframe capability, and initialize the driver
static errval_t init_sd(void) {
    errval_t err;

    struct capability sdhc_c;
    err = cap_direct_identify(dev_cap_sdhc2, &sdhc_c);
    assert(sdhc_c.type == ObjType_DevFrame);
    if(err_is_fail(err))
        return err;

    //map capability to sd card
    void *sdhc_base;
    err = paging_map_frame_attr(get_current_paging_state(), &sdhc_base, sdhc_c.u.ram.bytes, dev_cap_sdhc2, VREGION_FLAGS_READ_WRITE_NOCACHE);
    if(err_is_fail(err))
        return err;
    
    err = sdhc_init(&sd, sdhc_base);
    if(err_is_fail(err))
        return err;

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
    }

    spawn_set_rpc_handler(rpc_recv_handler);

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

    //Initialize sd card
    err = init_sd();
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "failed to initialize SD card\n");
    }

    debug_printf("Initialized SD card\n");

    // Booting second core
    for (int i = 1; i < 4; i++) {
        err = boot_core(i);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to boot core");
        }
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

    // map URPC frame to our addr
    uint8_t *urpc_addr;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_addr,
                           URPC_FRAME_SIZE, cap_urpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main mapping URPC frame");
        abort();
    }

    // BSP core was responsible for zeroing the URPC frame

    // Init URPC Client
    urpc_client[0] = malloc(sizeof(**urpc_client));
    if (urpc_client[0] == NULL) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to malloc urpc_client[0]");
        abort();
    }
    err = ump_chan_init_from_buf(urpc_client[0], urpc_addr, true);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to init urpc_client[0]");
        abort();
    }

    // Init URPC Server
    urpc_server[0] = malloc(sizeof(**urpc_server));
    if (urpc_server[0] == NULL) {
        DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "failed to malloc urpc_server[0]");
        abort();
    }
    err = ump_chan_init_from_buf(urpc_server[0], urpc_addr + UMP_CHAN_SHARED_FRAME_SIZE,
                                 false);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in app_main init urpc_server[0]");
        abort();
    }

    // create bootinfo
    size_t bi_size;
    err = ring_consumer_recv(&urpc_client[0]->recv, (void **)&bi, &bi_size);

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
    err = ring_consumer_recv(&urpc_client[0]->recv, (void **)&mm_strings_id,
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

    spawn_set_rpc_handler(rpc_recv_handler);

    grading_test_early();

    grading_test_late();

    // Start handling URPCs from core 0
    err = ump_chan_register_recv(urpc_server[0], get_default_waitset(),
                                 MKCLOSURE(urpc_handler, urpc_server[0]));
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
