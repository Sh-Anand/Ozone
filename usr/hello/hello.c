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

    printf("Trying to send number 42\n");
    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 42);
    assert(err_is_ok(err));
    printf("succesfully send number 42\n");

    char str[15] = "hello RPC world";
    printf("Trying to send string\n");
    err = aos_rpc_send_string(aos_rpc_get_init_channel(), str);

    struct capref ram;
    size_t size = 16384;
    ram_alloc(&ram, size);

    struct slot_allocator *sa = get_default_slot_allocator();
    struct capref frame;
    sa->alloc(sa, &frame);
    void *addr;
    cap_retype(frame, ram, 0, ObjType_Frame, size, 1);
    paging_map_frame_attr(get_current_paging_state(), &addr, size, frame, VREGION_FLAGS_READ_WRITE);

    printf("Mapped requested frame at %p\n", addr);
    char *data = (char*)addr;

    for (int i = 0; i < size; i++) {
        if (data[i] != 0) printf("READ ERROR\n");
        while(data[i] != 0);
        data[i] = (i / 128 + i / 16) % 256;
    }

    for (int i = 0; i < size; i++) {
        if (data[i] != (i / 128 + i / 16) % 256) printf("WRITE ERROR %d instead of %d\n", data[i], (i / 128 + i / 16) % 256);
        while(data[i] != (i / 128 + i / 16) % 256);
    }

    printf("Frame is write and readable...\n");

    printf("Try to spawn hello using RPC...\n");
    domainid_t pid;
    err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), "hello", 0, &pid);
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
