#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>
#include "test_paging.h"

void grading_setup_bsp_init(int argc, char **argv) { }

void grading_setup_app_init(struct bootinfo *bi) { }

void grading_setup_noninit(int *argc, char ***argv) { }

void grading_test_mm(struct mm *test) { }

__attribute__((unused)) static struct capref test_mem_map_fixed(lvaddr_t addr, size_t size)
{
    assert(size % 4 == 0);  // be sure to map multiples of int size
    struct slot_allocator *ca = get_default_slot_allocator();
    errval_t err;
    size_t actual;

    int *values = (void *)addr;
    struct capref frame;

    ca->alloc(ca, &frame);
    frame_create(frame, size, &actual);
    assert(actual >= size);
    err = paging_map_fixed_attr(get_current_paging_state(), addr, frame, size,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_fixed_attr");
        return frame;
    }

    for (int i = 0; i < size / 4; i++) {
        values[i] = 2 * i + 5;
        if (values[i] != 2 * i + 5) {
            printf("Instantly read %d instead of %d at %d (fixed)\n", values[i], i, i);
            while (1)
                ;
        }
    }

    for (int i = 0; i < size / 4; i++) {
        if (values[i] != 2 * i + 5) {
            printf("Read %d instead of %d at %d (fixed)\n", values[i], i, i);
            while (1)
                ;
        }
    }

    return frame;
}


__attribute__((unused)) static struct capref test_mem_alloc(lvaddr_t *addr, size_t size)
{
    assert(size % 4 == 0);  // be sure to map multiples of int size
    struct slot_allocator *ca = get_default_slot_allocator();
    errval_t err;
    size_t actual;

    struct capref frame;

    ca->alloc(ca, &frame);
    frame_create(frame, size, &actual);
    assert(actual >= size);
    err = paging_map_frame_attr(get_current_paging_state(), (void **)addr, size, frame,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_fixed_attr");
        return frame;
    }

    __attribute__((unused)) int *values = (void *)*addr;
    // debug_printf("mapped address: %020p, values: %020p\n", *addr, values);


    for (long int i = 0; i < size / 4; i++) {
        values[i] = i;
    }

    for (long int i = 0; i < size / 4; i++) {
        if (values[i] != i) {
            printf("Read %d instead of %d at %d\n", values[i], i, i);
            while (1)
                ;
        }
    }

    return frame;
}

extern struct mm aos_mm;

void grading_test_early(void)
{
    /*// test some fixed memory mapping (freeing not yet tested)
    __attribute__((unused)) lvaddr_t base = 3UL << 39;
    __attribute__((unused)) lvaddr_t addr0, addr1, addr2, addr3, addr4, addr5;
    __attribute__((unused)) struct capref fixed_frame0 = test_mem_map_fixed(base, 8192);
    base += 8192;
    __attribute__((unused)) struct capref fixed_frame1 = test_mem_map_fixed(base, 1 << 21);
    base += 1 << 21;
    __attribute__((unused)) struct capref fixed_frame2 = test_mem_map_fixed(base, 16384);
    base += 16384;
    __attribute__((unused)) struct capref fixed_frame3 = test_mem_map_fixed(base, 1 << 21);
    base += 1 << 21;
    __attribute__((unused)) struct capref fixed_frame4 = test_mem_map_fixed(base, 3 << 20);
    base += 3 << 20;
    __attribute__((unused)) struct capref fixed_frame5 = test_mem_map_fixed(base, 1 << 21);
    base += 1 << 21;

    __attribute__((unused)) struct capref frame0 = test_mem_alloc(&addr0, 4096);
    __attribute__((unused)) struct capref frame1 = test_mem_alloc(&addr1, 8192);
    __attribute__((unused)) struct capref frame2 = test_mem_alloc(&addr2, 16384);
    __attribute__((unused)) struct capref frame3 = test_mem_alloc(&addr3, 2097152 + 8192);
    __attribute__((unused)) struct capref frame4 = test_mem_alloc(&addr4, 3145728);
    __attribute__((unused)) struct capref frame5 = test_mem_alloc(
        &addr5, 3145728 + 8192);  // TODO: there seems to be an issue still here, where
                                  // something causes a pagefault*/

    grading_test_paging(&aos_mm, get_current_paging_state());
    grading_test_fixed_map_more_time(&aos_mm, get_current_paging_state(), 1000);
    grading_test_dynamic_map_more_time(&aos_mm, get_current_paging_state(), 1000);

    // debug_printf("tests complete\n");
    // while(1);
}

static void delay(int count)
{
    volatile int a[3] = { 0, 1 };
    for (int i = 0; i < count; i++) {
        a[2] = a[0];
        a[0] = a[1];
        a[1] = a[2];
    }
}

// static void print_proc(domainid_t pid, struct capref dispatcher, const char *name) {
//     DEBUG_PRINTF("PROC: pid = %d, name = %s\n", pid, name);
// }

void grading_test_late(void)
{
    struct spawninfo info[21];
    domainid_t pid = -1;
    errval_t err;

    //    DEBUG_PRINTF("Run spawnTester 10...\n");
    //         err = spawn_load_cmdline("spawnTester 10", &info[0], &pid);
    //         assert(err_is_ok(err));
    //         assert(pid != -1);

//    DEBUG_PRINTF("Run 10 spawnTester 10...\n");
//    for (int i = 1; i <= 10; i++) {
//        err = spawn_load_cmdline("spawnTester 10", &info[0], &pid);
//        assert(err_is_ok(err));
//        assert(pid != -1);
//        printf("%d-th call succeed\n", i);
//    }

//    domainid_t *pids = NULL;
//    size_t pid_count = 0;
//    err = spawn_get_all_pids(&pids, &pid_count);
//    if (err_is_fail(err)) {
//        DEBUG_PRINTF("  Getting all PIDs failed.\n");
//    }
//    assert(pids != NULL && "NULL pids");
//    DEBUG_PRINTF("  Get %lu PID(s):\n", pid_count);
//
//    for (int i = 0; i < pid_count; i++) {
//        char *name;
//        err = spawn_get_name(pids[i], &name);
//        if (err_is_fail(err)) {
//            DEBUG_PRINTF("  Getting name failed.\n");
//        }
//        DEBUG_PRINTF("  %u %s\n", pids[i], name);
//        free(name);
//    }

    DEBUG_PRINTF("Start first hello with spawn_load_by_name...\n");
    err = spawn_load_by_name("hello", &info[0], &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "spawn_load_by_name failed");
    }
    assert(pid != -1);


    delay(200000000);

    //    DEBUG_PRINTF("Kill the first hello...\n");
    //    err = invoke_dispatcher_stop(info[0].dispatcher_cap_in_parent);
    //    assert(err_is_ok(err));

    //    delay(20000000);

    //    DEBUG_PRINTF("Print proc list...\n");
    //    proc_list_enum(&list, print_proc);
    //
    //    DEBUG_PRINTF("Start 4 hello with spawn_load_argv...\n");
    //    char *binary_name = "hello";
    //    char *arg = "welcome";
    //    char *argv[] = {binary_name, arg, NULL};
    //    for (int i = 1; i <= 4; i++) {
    //        err = spawn_load_argv(2, argv, &info[i], &pid);
    //        assert(err_is_ok(err));
    //        proc_list_insert(&list, pid, info[i].dispatcher_cap_in_parent,
    //        info[i].binary_name); printf("%d-th call succeed\n", i);
    //    }
    //
    //    DEBUG_PRINTF("Print proc list again...\n");
    //    proc_list_enum(&list, print_proc);
    //
    //    for (int i = 1; i <= 4; i++) {
    //        err = invoke_dispatcher_stop(info[i].dispatcher_cap_in_parent);
    //        assert(err_is_ok(err));
    //        proc_list_remove(&list, info[i].pid);
    //    }
    //
    //    delay(500000);
    //
    //    DEBUG_PRINTF("Print proc list again...\n");
    //    proc_list_enum(&list, print_proc);
    //
    //    assert(err_is_ok(err));
}
