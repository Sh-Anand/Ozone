//
// Created by Zikai Liu on 4/2/22.
//

#include "test_paging.h"
#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>

static struct capref test_alloc_frame_success(struct mm *mm, size_t size, bool no_print)
{
    errval_t err;
    struct capref cap = NULL_CAP;
    
    // DEBUG_PRINTF("frame_alloc size = %lu\n", size)
    err = frame_alloc(&cap, size, NULL);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "frame_alloc failed\n");
    }

    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "fail to identify the returned capability\n");
    }
    if (c.type != ObjType_Frame) {
        USER_PANIC("capability is not ObjType_Frame, actual = %d\n", c.type);
    }
    if (!no_print) {
        DEBUG_PRINTF("get frame base = 0x%lx, size = %lu\n", c.u.frame.base, c.u.frame.bytes);
    }
    if (c.u.frame.bytes < size) {
        USER_PANIC("requested size %lu but got smaller size %lu\n", size, c.u.frame.bytes);
    }
    if (ROUND_UP(c.u.ram.base, BASE_PAGE_SIZE) != c.u.ram.base) {
        USER_PANIC("address 0x%lx is not aligned to %lx\n", c.u.ram.base, BASE_PAGE_SIZE);
    }

    return cap;
}

static void test_alloc_and_fixed_map_frame_success(struct mm *mm, struct paging_state *st, size_t vaddr, size_t size,
                                                   bool no_print)
{
    struct capref frame;
    frame = test_alloc_frame_success(mm, size, no_print);

    errval_t err;
    err = paging_map_fixed_attr(st, vaddr, frame, size, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_map_fixed_attr failed\n");
    }

    memset((void *)vaddr, 0, size);
    if (!no_print) {
        DEBUG_PRINTF("fixed map frame to 0x%lx/%lu success\n", vaddr, size);
    }
}

static void test_alloc_and_dynamic_map_frame_success(struct mm *mm, struct paging_state *st, size_t size, bool no_print)
{
    struct capref frame;
    frame = test_alloc_frame_success(mm, size, no_print);

    void *vaddr = NULL;

    errval_t err;
    err = paging_map_frame_attr(st, &vaddr, size, frame, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_map_frame_attr failed\n");
    }

    memset(vaddr, 0, size);
    if (!no_print) {
        DEBUG_PRINTF("dynamic map frame to %p/%lu success\n", vaddr, size);
    }
}

static void test_paging_fixed_map_fail(struct paging_state *st, lvaddr_t vaddr, struct capref frame, size_t bytes, int flags)
{
    errval_t err;
    err = paging_map_fixed_attr(st, vaddr, frame, bytes, flags);
    if (err_is_ok(err)) {
        USER_PANIC_ERR(err, "  MM: paging_map_fixed_attr succeeded unexpected\n");
    }
}

void grading_test_paging(struct mm *mm, struct paging_state *st)
{
    DEBUG_PRINTF("Start grading_test_paging...\n");
    uint64_t vaddr_base = VMSAv8_64_L0_SIZE << 4;  // avoid conflict with slab allocators
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base, BASE_PAGE_SIZE, false);
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base + BASE_PAGE_SIZE, BASE_PAGE_SIZE, false);
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base + 4 * BASE_PAGE_SIZE, BASE_PAGE_SIZE, false);
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base + 2 * BASE_PAGE_SIZE, BASE_PAGE_SIZE * 2, false);
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base + 5 * BASE_PAGE_SIZE, BASE_PAGE_SIZE * 4, false);
    test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base + VMSAv8_64_L0_SIZE, BASE_PAGE_SIZE * 2048, false);

    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE, false);
    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE, false);
    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE, false);
    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE * 2, false);
    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE * 4, false);
    test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE * 2048, false);

    struct capref frame = test_alloc_frame_success(mm, BASE_PAGE_SIZE, false);

    // Index 0 L1 page table
    DEBUG_PRINTF("[Try Paging to Index 0 L1]\n");
    test_paging_fixed_map_fail(st, 0, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    test_paging_fixed_map_fail(st, VMSAv8_64_L0_SIZE - BASE_PAGE_SIZE, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    // In kernel space

    DEBUG_PRINTF("[Try Paging to kernel space addresses]\n");
    test_paging_fixed_map_fail(st, -1, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    test_paging_fixed_map_fail(st, BIT(48), frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);

    // Invalid caps
    //    DEBUG_PRINTF("[Try Paging with Invalid Caps]\n");
    //    test_paging_fixed_map_fail(st, VMSAv8_64_L0_SIZE << 7, NULL_CAP, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    //    test_paging_fixed_map_fail(st, VMSAv8_64_L0_SIZE << 7, cap_vroot, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    //    test_paging_fixed_map_fail(st, VMSAv8_64_L0_SIZE << 7, cap_dispatcher, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);

    // Tricky sizes
    //    DEBUG_PRINTF("[Try Paging with Invalid Size]\n");
    //    test_paging_map_su(st, VMSAv8_64_L0_SIZE << 7, cap_dispatcher, 0, VREGION_FLAGS_READ_WRITE);
    //    test_paging_map_fail(st, VMSAv8_64_L0_SIZE << 7, cap_dispatcher, 1, VREGION_FLAGS_READ_WRITE);
    // -1 is not tested since it span multiple tables

    cap_delete(frame);
}

void grading_test_fixed_map_more_time(struct mm *mm, struct paging_state *st, int count)
{
    DEBUG_PRINTF("[Fixed map for %d times]\n", count);
    uint64_t vaddr_base = VMSAv8_64_L0_SIZE << 6;  // avoid conflict with slab allocators
    for (int i = 0; i < count; i++) {
        test_alloc_and_fixed_map_frame_success(mm, st, vaddr_base, BASE_PAGE_SIZE * (i / 4 + 1), true);
        vaddr_base += BASE_PAGE_SIZE * (i + 1) * 2;
        if (i % 100 == 0) {
            DEBUG_PRINTF("  %d times...\n", i);
        }
    }
    DEBUG_PRINTF("  %d times done\n", count);
}

void grading_test_dynamic_map_more_time(struct mm *mm, struct paging_state *st, int count)
{
    DEBUG_PRINTF("[Dynamic map for %d times]\n", count);
    for (int i = 0; i < count; i++) {
        test_alloc_and_dynamic_map_frame_success(mm, st, BASE_PAGE_SIZE * (i / 4 + 1), true);
        if (i % 100 == 0) {
            DEBUG_PRINTF("  %d times...\n", i);
        }
    }
    DEBUG_PRINTF("  %d times done\n", count);
}
