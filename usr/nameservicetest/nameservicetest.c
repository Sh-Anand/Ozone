/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/nameserver.h>
#include "err.h"


#define PANIC_IF_FAIL(err, msg)                                                          \
    if (err_is_fail(err)) {                                                              \
        USER_PANIC_ERR(err, msg);                                                        \
    }

#define SERVICE_NAME "myservicename"
#define SERVICE_NAME2 "myservicename2"
#define TEST_BINARY "nameservicetest"

static int printf_in_frame(struct capref *frame, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    errval_t err;

    void *buf;
    err = frame_alloc(frame, BASE_PAGE_SIZE, NULL);
    PANIC_IF_FAIL(err, "failed to alloc tx frame\n");

    err = paging_map_frame_complete(get_current_paging_state(), &buf, *frame);
    PANIC_IF_FAIL(err, "failed map tx frame\n");

    memset(buf, 0, BASE_PAGE_SIZE);
    int ret = vsprintf(buf, format, args);

    err = paging_unmap(get_current_paging_state(), buf);
    PANIC_IF_FAIL(err, "failed unmap tx frame\n");

    return ret;
}

static void debug_printf_frame(struct capref rx_cap, const char *name) {
    errval_t err;

    void *buf;
    err = paging_map_frame_complete(get_current_paging_state(), &buf, rx_cap);
    PANIC_IF_FAIL(err, "failed map rx_cap\n");
    debug_printf("%s: got a frame cap \"%s\"\n", name,
                 (const char *)buf);
    err = paging_unmap(get_current_paging_state(), buf);
    PANIC_IF_FAIL(err, "failed unmap rx_cap\n");
}

/*
 * ============================================================================
 * Client
 * ============================================================================
 */

static char *myrequest = "request !!";

static void run_client(void)
{
    errval_t err;

    /* look up service using name server */
    nameservice_chan_t chan;
    err = nameservice_lookup(SERVICE_NAME, &chan);
    PANIC_IF_FAIL(err, "failed to lookup service\n");

    debug_printf("client: got the service %p. Sending request \"%s\"\n", chan, myrequest);

    void *request = myrequest;
    size_t request_size = strlen(myrequest);

    struct capref tx_cap;
    printf_in_frame(&tx_cap, "client of process %u on core %u", disp_get_domain_id(),
                    disp_get_core_id());

    struct capref rx_cap;
    err = slot_alloc(&rx_cap);
    PANIC_IF_FAIL(err, "failed to alloc rx_cap\n");

    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_size, &response, &response_bytes, tx_cap,
                          rx_cap);
    PANIC_IF_FAIL(err, "failed to do the nameservice rpc\n");

    debug_printf("client: got response \"%s\"\n", (char *)response);

    struct capability c;
    err = cap_direct_identify(rx_cap, &c);
    if (err == SYS_ERR_CAP_NOT_FOUND) {
        debug_printf("client: no cap received\n");
    } else {
        switch (c.type) {
        case ObjType_Frame: {
            debug_printf_frame(rx_cap, "client");
        } break;
        default:
            debug_printf("client: got a cap with type %u\n", c.type);
        }
    }
}

/*
 * ============================================================================
 * Server
 * ============================================================================
 */

static char *myresponse = "reply!!";

static volatile int received_count = 0;

static void server_recv_handler(void *st, void *message, size_t bytes, void **response,
                                size_t *response_bytes, struct capref rx_cap,
                                struct capref *tx_cap)
{
    debug_printf("server: got a request \"%s\"\n", (char *)message);

    received_count++;

    errval_t err;

    // Decode the received cap
    if (!capref_is_null(rx_cap)) {
        struct capability c;
        err = cap_direct_identify(rx_cap, &c);
        PANIC_IF_FAIL(err, "server: failed to identify rx_cap\n");

        switch (c.type) {
        case ObjType_Frame: {
            debug_printf_frame(rx_cap, "server");
        } break;
        default:
            debug_printf("server: got a cap with type %u\n", c.type);
        }
    }

    // Send a frame back
    printf_in_frame(tx_cap, "server of process %u on core %u", disp_get_domain_id(),
                    disp_get_core_id());

    *response = myresponse;
    *response_bytes = strlen(myresponse);
}

static void test_enumerate(char *query)
{
    size_t count = 256;
    char *names[256];
    errval_t err = nameservice_enumerate(query, &count, names);
    PANIC_IF_FAIL(err, "failed to enumerate service\n");
    debug_printf("server: enumerate \"%s\" got %lu services:\n", query, count);
    for (size_t i = 0; i < count; i++) {
        debug_printf("%lu. %s\n", i + 1, names[i]);
        free(names[i]);
    }
}
static void run_server(void)
{
    errval_t err;

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME);
    err = nameservice_register(SERVICE_NAME, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME2);
    err = nameservice_register(SERVICE_NAME2, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    test_enumerate("");
    test_enumerate(SERVICE_NAME);
    test_enumerate(SERVICE_NAME2);

    domainid_t did;
    for (int i = 0; i < 8; ++i) {
        coreid_t core = (disp_get_core_id() + i) % 4;
        debug_printf("spawning test binary '%s' on core %u\n", TEST_BINARY, core);
        err = aos_rpc_process_spawn(get_init_rpc(), TEST_BINARY " a", core, &did);
        PANIC_IF_FAIL(err, "failed to spawn test\n");
    }

    while (received_count < 8) {
        event_dispatch(get_default_waitset());
    }

    debug_printf("deregister '%s'\n", SERVICE_NAME2);
    err = nameservice_deregister(SERVICE_NAME2);
    PANIC_IF_FAIL(err, "failed to deregister...\n");

    test_enumerate("");
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(int argc, char *argv[])
{
    if (argc == 2) {
        debug_printf("nameservicetest: running client!\n");
        run_client();
    } else {
        debug_printf("nameservicetest: running server!\n");
        run_server();
    }

    return EXIT_SUCCESS;
}
