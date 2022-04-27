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
#include <aos/except.h>
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

static void print_err_if_any(errval_t err)
{
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
    }
}

struct thread_param {
    size_t id;
    volatile bool should_exit;
};

static int thread_func(void *params)
{
    // struct thread_param *p = params;
    DEBUG_PRINTF("Trying to malloc 64MB...\n");
    size_t region_size = 64 * 1024 * 1024;
    char *b = malloc(region_size);
    if (b == NULL) {
        print_err_if_any(LIB_ERR_MALLOC_FAIL);
    } else {
        DEBUG_PRINTF("malloc succeeded, going to memset whole 64MB, will take "
               "some time...\n");
        memset(b, 0, region_size);
        DEBUG_PRINTF("memset succeeded\n");
    }
    return EXIT_SUCCESS;
}

#define MAX_THREAD_COUNT 256
struct thread *threads[MAX_THREAD_COUNT] = { NULL };
struct thread_param params[MAX_THREAD_COUNT];
size_t thread_count = 0;

int main(int argc, char *argv[])
{
    errval_t err;

    printf("Hello, world! from userspace and through RPC, presented by AOS team 1\n");
    for (int i = 0; i < argc; i++) {
        printf("arg[%d]: %s\n", i, argv[i]);
    }

    if (argc < 2 || strcmp(argv[1], "AOS") != 0) {
        printf("Goodbye world!");
        return EXIT_SUCCESS;
    }

    printf("Entering shell since argv[1] == \"AOS\"\n");

    char buf[SHELL_BUF_SIZE];
    uword_t offset;
    while (1) {  // command loop
        putchar('$');
        putchar(' ');
        fflush(stdout);

        offset = 0;
        while (1) {  // character loop
            char c = getchar();
            if (c == '\n' || c == '\r') {
                putchar('\n');
                buf[offset] = '\0';
                if (offset == 0) {
                    // Do nothing, fall back to the next command
                } else if (strcmp(buf, "help") == 0) {
                    printf("Available commands:\n"
                           "  exit\n"
                           "RPC:\n"
                           "  send_num\n"
                           "  send_str\n"
                           "  send_large_str\n"
                           "  get_ram\n"
                           "  get_pids\n"
                           "Paging:\n"
                           "  fault_read\n"
                           "  fault_write\n"
                           "  fault_null\n"
                           "  large_malloc\n"
                           "  self_paging\n"
                           "Threads:\n"
                           "  mt_self_paging\n"
                           "Spawn:\n"
                           "  spawn <core> <command line>\n"
                           "  <command line to spawn on the current core>\n");

                } else if (strcmp(buf, "exit") == 0) {
                    printf("Goodbye, world!\n");
                    return EXIT_SUCCESS;

                } else if (strcmp(buf, "fault_read") == 0) {
                    printf("%d\n", *((int *)(VMSAv8_64_L0_SIZE * 256)));
                    printf("SHOULD NOT REACH HERE\n");
                    return EXIT_FAILURE;

                } else if (strcmp(buf, "fault_write") == 0) {
                    *((int *)(VMSAv8_64_L0_SIZE * 128)) = 42;
                    printf("SHOULD NOT REACH HERE\n");
                    return EXIT_FAILURE;

                } else if (strcmp(buf, "large_malloc") == 0) {
                    printf("Trying to malloc 64MB...\n");
                    size_t region_size = 64 * 1024 * 1024;
                    char *b = malloc(region_size);
                    if (b == NULL) {
                        print_err_if_any(LIB_ERR_MALLOC_FAIL);
                    } else {
                        printf("malloc succeeded, going to memset whole 64MB, will take "
                               "some time...\n");
                        memset(b, 0, region_size);
                        printf("memset succeeded\n");
                    }

                } else if (strcmp(buf, "self_paging") == 0) {
                    printf("Trying to malloc 1GB...\n");
                    size_t region_size = 1 * 1024LU * 1024LU * 1024LU;
                    char *b = malloc(region_size);
                    if (b == NULL) {
                        print_err_if_any(LIB_ERR_MALLOC_FAIL);
                    } else {
                        printf("malloc succeeded, going to memset a few pages\n");
                        memset(b, 0, BASE_PAGE_SIZE);
                        memset(b + 512LU * 1024LU * 1024LU, 0, BASE_PAGE_SIZE);
                        memset(b + region_size - BASE_PAGE_SIZE, 0, BASE_PAGE_SIZE);
                        printf("memset succeeded\n");
                    }

                } else if (strcmp(buf, "send_num") == 0) {
                    printf("Trying to send number 42...\n");
                    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 42);
                    print_err_if_any(err);
                    printf("Successfully send number 42\n");

                } else if (strcmp(buf, "send_str") == 0) {
                    char str[15] = "Hello RPC world";
                    printf("Trying to send a small string...\n");
                    err = aos_rpc_send_string(aos_rpc_get_init_channel(), str);
                    print_err_if_any(err);
                    printf("Successfully send string\n");

                } else if (strcmp(buf, "send_large_str") == 0) {
                    printf("Trying to send a large string...\n");
                    err = aos_rpc_send_string(aos_rpc_get_init_channel(), large_str);
                    print_err_if_any(err);
                    printf("Successfully send large string\n");

                } else if (strcmp(buf, "get_ram") == 0) {
                    size_t size = 16384;

                    printf("Trying to get a frame of size %lu...\n", size);
                    struct capref ram;
                    err = ram_alloc(&ram, size);
                    print_err_if_any(err);
                    printf("Successfully get the frame\n");

                    struct capref frame;
                    err = slot_alloc(&frame);
                    print_err_if_any(err);

                    void *addr;
                    err = cap_retype(frame, ram, 0, ObjType_Frame, size, 1);
                    print_err_if_any(err);
                    err = paging_map_frame_attr(get_current_paging_state(), &addr, size,
                                                frame, VREGION_FLAGS_READ_WRITE);
                    print_err_if_any(err);
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

                } else if (strcmp(buf, "get_pids") == 0) {
                    domainid_t *pids = NULL;
                    size_t pid_count = 0;
                    err = aos_rpc_process_get_all_pids(aos_rpc_get_process_channel(),
                                                       &pids, &pid_count);
                    if (err_is_fail(err)) {
                        DEBUG_PRINTF("  Getting all PIDs failed.\n");
                        return EXIT_FAILURE;
                    }
                    assert(pids != NULL && "NULL pids");
                    DEBUG_PRINTF("  Get %lu PID(s):\n", pid_count);

                    for (int i = 0; i < pid_count; i++) {
                        char *name;
                        err = aos_rpc_process_get_name(aos_rpc_get_process_channel(),
                                                       pids[i], &name);
                        if (err_is_fail(err)) {
                            DEBUG_PRINTF("  Getting name failed.\n");
                            return EXIT_FAILURE;
                        }
                        DEBUG_PRINTF("  %u %s\n", pids[i], name);
                        free(name);
                    }

                    free(pids);
                } else if (strcmp(buf, "sleep") == 0) {
                    sleep(1);

                } else if (strcmp(buf, "mt_self_paging") == 0) {
                    printf("Going to create 16 threads...\n");

                    for (int i = 0; i < 16; i++) {
                        params[thread_count].id = thread_count;
                        params[thread_count].should_exit = false;
                        threads[thread_count] = thread_create(thread_func,
                                                              &params[thread_count]);
                        assert(threads[thread_count] != NULL);

                        thread_count++;
                    }

                    for (int i = 0; i < 16; i++) {
                        thread_join(threads[i], NULL);
                    }
                } else if (strncmp(buf, "spawn ", 6) == 0) {
                    char *cmdline = NULL;

                    coreid_t core;
                    core = strtol(buf + 6, &cmdline, 10);
                    assert(core <= 1);

                    while(*cmdline == ' ') cmdline++;

                    domainid_t pid = 0;
                    printf("Hello is going to exit to unblock init!\n");
                    err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), cmdline, core,
                                                &pid);
                    print_err_if_any(err);
                    return EXIT_SUCCESS;
                } else {
                    domainid_t pid = 0;
                    printf("Hello is going to exit to unblock init!\n");
                    err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), buf, disp_get_current_core_id(),
                                                &pid);
                    print_err_if_any(err);
                    return EXIT_SUCCESS;
                }
                break;  // prompt for the next command

            } else if (c == 127) {
                if (offset > 0) {
                    printf("\b \b");  // destructive backspace
                    fflush(stdout);
                    offset--;
                }
            } else {
                putchar(c);  // echo
                fflush(stdout);
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
