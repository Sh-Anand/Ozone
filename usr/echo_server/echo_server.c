/**
 * \file
 * \brief Echo server application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos_rpc.h>
#include <aos/deferred.h>
#include <aos/nameserver.h>
#include <aos/enet.h>

enet_udp_socket socket;

static void udp_listener(ip_addr_t ip, uint16_t port, void *data, size_t bytes) {
    debug_printf("Received %i bytes from %08X:%i\n", bytes, ip, port);
    enet_udp_send(data, bytes, ip, port, socket);
}

int main(int argc, char *argv[])
{
    aos_rpc_serial_release(aos_rpc_get_serial_channel()); // We dont want stdin!

    if (argc != 2) {
        printf("Please provide exactly one argument (the port number)!\n");
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);

    if (port <= 0 || port >= 65536) {
        printf("The port number has to be a number between 1 and 65535!\n");
        return EXIT_FAILURE;
    }

    while (err_is_fail(enet_udp_create_socket(port, &socket, &udp_listener))) {
        debug_printf("Could not create socket, will try again.\n");
        barrelfish_usleep(1000000);
    }

    debug_printf("Now listening on %i\n", socket);

    while(1) event_dispatch(get_default_waitset());

    return EXIT_SUCCESS;
}
