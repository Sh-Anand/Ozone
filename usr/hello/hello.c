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

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace, presented by AOS team 1\n");
    for (int i = 0; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }
    for (int i = 5; i >= 0; i--) {
        printf("Countdown %d/5...\n", i);
        // sleep(1);
    }
    printf("Goodbye, world!\n");
    return EXIT_SUCCESS;
}
