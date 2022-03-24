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
    printf("Going to print INFINITELY...\n");
    while(1) {
        printf("+");
        fflush(stdout);
        delay(20000000);
    }
    printf("Goodbye, world!\n");
    return EXIT_SUCCESS;
}
