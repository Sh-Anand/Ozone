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

#define SHELL_BUF_SIZE 256

const char *large_str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, "
                        "sed do eiusmod tempor incididunt ut labore et dolore magna "
                        "aliqua. Ut enim ad minim veniam, quis nostrud exercitation "
                        "ullamco laboris nisi ut aliquip ex ea commodo consequat. "
                        "Duis aute irure dolor in reprehenderit in voluptate velit "
                        "esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
                        "occaecat cupidatat non proident, sunt in culpa qui officia "
                        "deserunt mollit anim id est laborum.";

int main(int argc, char *argv[])
{
    errval_t err;
    printf("Hello, world! from userspace and through RPC, presented by AOS team 1\n");
    for (int i = 0; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }

    char str0[15] = "Hello RPC world";
    printf("Trying to send a small string...\n");
    err = aos_rpc_send_string(aos_rpc_get_init_channel(), str0);
    assert(err_is_ok(err));
    printf("Successfully send string\n");

    printf("Trying to send a large string...\n");
    err = aos_rpc_send_string(aos_rpc_get_init_channel(), large_str);
    assert(err_is_ok(err));
    printf("Successfully send large string\n");
    return EXIT_SUCCESS;

    char buf[SHELL_BUF_SIZE];
    uword_t offset;
    while (1) {  // command loop
        printf("$ ");

        offset = 0;
        while (1) {  // character loop
            char c = getchar();
            if (c == '\n' || c == '\r') {
                putchar('\n');
                buf[offset] = '\0';
                if (offset == 0) {
                    // Do nothing, fall back to the next command
                } else if (strcmp(buf, "help") == 0) {
                    printf("Available commands:\n  hello\n  exit\n  send_num\n  "
                           "send_str\n  send_large_str\n  get_ram\n  "
                           "Others are interpreted as spawn commands\n");

                } else if (strcmp(buf, "hello") == 0) {
                    printf("Hello from AOS team 1\n");

                } else if (strcmp(buf, "exit") == 0) {
                    printf("Goodbye, world!\n");
                    return EXIT_SUCCESS;

                } else if (strcmp(buf, "send_num") == 0) {
                    printf("Trying to send number 42...\n");
                    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 42);
                    assert(err_is_ok(err));
                    printf("Successfully send number 42\n");

                } else if (strcmp(buf, "send_str") == 0) {
                    char str[15] = "Hello RPC world";
                    printf("Trying to send a small string...\n");
                    err = aos_rpc_send_string(aos_rpc_get_init_channel(), str);
                    assert(err_is_ok(err));
                    printf("Successfully send string\n");

                } else if (strcmp(buf, "send_large_str") == 0) {
                    printf("Trying to send a large string...\n");
                    err = aos_rpc_send_string(aos_rpc_get_init_channel(), large_str);
                    assert(err_is_ok(err));
                    printf("Successfully send large string\n");

                } else if (strcmp(buf, "get_ram") == 0) {
                    size_t size = 16384;

                    printf("Trying to get a frame of size %lu...\n", size);
                    struct capref ram;
                    err = ram_alloc(&ram, size);
                    assert(err_is_ok(err));
                    printf("Successfully get the frame\n");

                    struct capref frame;
                    err = slot_alloc(&frame);
                    assert(err_is_ok(err));

                    void *addr;
                    err = cap_retype(frame, ram, 0, ObjType_Frame, size, 1);
                    assert(err_is_ok(err));
                    err = paging_map_frame_attr(get_current_paging_state(), &addr, size,
                                                frame, VREGION_FLAGS_READ_WRITE);
                    assert(err_is_ok(err));
                    printf("Mapped requested frame at %p\n", addr);

                    char *data = addr;
                    for (int i = 0; i < size; i++) {
                        if (data[i] != 0) {
                            printf("READ ERROR\n");
                        }
                        while (data[i] != 0)
                            /* hanging */;
                        data[i] = (i / 128 + i / 16) % 256;
                    }

                    for (int i = 0; i < size; i++) {
                        if (data[i] != (i / 128 + i / 16) % 256) {
                            printf("WRITE ERROR %d instead of %d\n", data[i],
                                   (i / 128 + i / 16) % 256);
                        }
                        while (data[i] != (i / 128 + i / 16) % 256)
                            /* hanging */;
                    }

                    printf("The frame is write and readable...\n");

                } else {
                    printf("Unknown command: %s\n", buf);
                }
                break;  // prompt for the next command

            } else if (c == 127) {
                if (offset > 0) {
                    printf("\b \b");  // destructive backspace
                    offset--;
                }
            } else {
                putchar(c);  // echo
                buf[offset] = c;
                offset++;
                if (offset == SHELL_BUF_SIZE) {
                    printf("\nInput exceeds %d characters, resetting\n", SHELL_BUF_SIZE);
                    break;  // prompt for the next command
                }
            }
        }
    }

    return EXIT_SUCCESS;
}
