/**
 * \file
 * \brief Hello world application
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

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <unistd.h>
#include "aos/aos_rpc.h"

static void delay(int count) {
    volatile int a[3]= {0, 1};
    for (int i = 0; i < count; i++) {
        a[2] = a[0];
        a[0] = a[1];
        a[1] = a[2];
    }
}

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace, presented by AOS team 1\n");
    for (int i = 0; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }

    // printf("Try to spawn hello using RPC...\n");
    // domainid_t pid;
    // errval_t err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), "hello", 0, &pid);
    // assert(err_is_ok(err));
    // printf("spawn new hello: %u\n", pid);

    struct capref ram = NULL_CAP;
    size_t size = 0;
    struct aos_rpc *init_chan = aos_rpc_get_process_channel();
    printf("Got %p\n", init_chan);
    aos_rpc_get_ram_cap(init_chan, 4096, 4096, &ram, &size);
    printf("Got %ld /%ld)\n", size, get_cap_addr(ram));

    printf("Going to print INFINITELY...\n");
    while(1) {
        printf("+");
        fflush(stdout);
        delay(20000000);
    }
    printf("Goodbye, world!\n");
    return EXIT_SUCCESS;
}
