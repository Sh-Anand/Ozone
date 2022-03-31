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
    errval_t err;
    printf("Hello, world! from userspace, presented by AOS team 1\n");
    for (int i = 0; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }

    // printf("Try to spawn hello using RPC...\n");
    // domainid_t pid;
    // err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), "hello", 0, &pid);
//    if (err_is_fail(err)) {
//        USER_PANIC_ERR(err, "failed to aos_rpc_process_spawn");
//    }
    // printf("spawn new hello: %u\n", pid);

    printf("Trying to send number 42\n");
    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 42);
    assert(err_is_ok(err));
    printf("succesfully send number 42\n");

    char str[15] = "hello RPC world";
    printf("Trying to send string\n");
    err = aos_rpc_send_string(aos_rpc_get_init_channel(), str);
    assert(err_is_ok(err));
    printf("succesfully sent string\n");

    printf("Going to print INFINITELY...\n");
    while(1) {
        printf("+");
        fflush(stdout);
        delay(20000000);
    }
    printf("Goodbye, world!\n");
    return EXIT_SUCCESS;
}
