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

#include <aos/deferred.h>
#include <aos/nameserver.h>
#include <aos/enet.h>

enet_udp_socket socket;
ip_addr_t response_ip = 0;
uint16_t response_port = 0;

static void udp_listener(ip_addr_t ip, uint16_t port, void *data, size_t bytes) {
    response_ip = ip;
    response_port = port;
    printf("%.*s", bytes, data);
}

static int background_listener(void *v) {
    while(true) event_dispatch(get_default_waitset());

    return 0;
}

#define BUF_SIZE 1024 // Should fit into an UDP Packet

int main(int argc, char *argv[])
{
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

    setbuffer(stdin, NULL, 0);
    char *buf = malloc(BUF_SIZE);
    int pos = 0;
    thread_create(&background_listener, NULL);
    while (1) {
        buf[pos] = getchar();
        if (buf[pos] == '\r') buf[pos] = '\n'; // Not clean, but we want the output to be formated nicely

        if (buf[pos] == '\x03') { // CTRL + C
            if (err_is_ok(enet_udp_destroy_socket(socket))) return EXIT_SUCCESS;
            else return EXIT_FAILURE;
        }

        printf("%c", buf[pos]); // Echo to stdout
        if (buf[pos] == '\n' || pos + 1 == BUF_SIZE) {
            if (response_ip && response_port) enet_udp_send(buf, pos + 1, response_ip, response_port, socket);
            pos = 0;
        } else pos++;
    }

    return EXIT_SUCCESS;
}
