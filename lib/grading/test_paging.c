//
// Created by Zikai Liu on 4/2/22.
//

#include "test_paging.h"
#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>

#define UNMAP_FOR_ALL_TEST true

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

static void test_fixed_mapping_success(struct mm *mm, struct paging_state *st,
                                       size_t vaddr, size_t size, bool no_print,
                                       bool unmap)
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

    if (unmap) {
        err = paging_unmap(st, (void *)vaddr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_unmap failed\n");
        }
        if (!no_print) {
            DEBUG_PRINTF("unmap 0x%lx/%lu success\n", vaddr, size);
        }
        err = cap_destroy(frame);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "cap_destroy failed\n");
        }
    }
}

static void test_dynamic_mapping_success(struct mm *mm, struct paging_state *st,
                                         size_t size, bool no_print, bool unmap)
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

    if (unmap) {
        err = paging_unmap(st, (void *)vaddr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_unmap failed\n");
        }
        if (!no_print) {
            DEBUG_PRINTF("unmap %p/%lu success\n", vaddr, size);
        }
        err = cap_destroy(frame);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "cap_destroy failed\n");
        }
    }
}

static void test_mapping_alloc_success(struct mm *mm, struct paging_state *st, size_t size,
                                       void **vaddr, bool no_print, bool unmap)
{
    *vaddr = NULL;
    errval_t err;
    err = paging_alloc(st, vaddr, size, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_alloc failed\n");
    }
    if (!no_print) {
        DEBUG_PRINTF("paging_alloc to %p/%lu success\n", *vaddr, size);
    }
    assert(*vaddr != NULL);
    if (unmap) {
        err = paging_unmap(st, (void *)vaddr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_unmap failed\n");
        }
        if (!no_print) {
            DEBUG_PRINTF("unmap %p/%lu success\n", vaddr, size);
        }
    }
}

static void test_alloc_plus_fixed_mapping_success(struct mm *mm, struct paging_state *st,
                                                  size_t size, bool no_print, bool unmap)
{
    struct capref frame;
    frame = test_alloc_frame_success(mm, size, no_print);

    void *vaddr = NULL;

    errval_t err;
    err = paging_alloc(st, &vaddr, size, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_alloc failed\n");
    }
    assert(vaddr != NULL);

    err = paging_map_fixed_attr(st, (lvaddr_t)vaddr, frame, size, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_map_fixed_attr failed\n");
    }

    memset(vaddr, 0, size);
    if (!no_print) {
        DEBUG_PRINTF("alloc + fixed map frame to %p/%lu success\n", vaddr, size);
    }

    if (unmap) {
        err = paging_unmap(st, (void *)vaddr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_unmap failed\n");
        }
        if (!no_print) {
            DEBUG_PRINTF("unmap %p/%lu success\n", vaddr, size);
        }
        err = cap_destroy(frame);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "cap_destroy failed\n");
        }
    }
}

static void test_paging_fixed_map_fail(struct paging_state *st, lvaddr_t vaddr, struct capref frame, size_t bytes, int flags)
{
    errval_t err;
    err = paging_map_fixed_attr(st, vaddr, frame, bytes, flags);
    if (err_is_ok(err)) {
        USER_PANIC_ERR(err, "paging_map_fixed_attr succeeded unexpected\n");
    }
}

static void test_alloc_with_alignment_success(struct mm *mm, struct paging_state *st,
                                              size_t size, size_t alignment,
                                              bool no_print, bool unmap)
{
    void *vaddr = NULL;

    errval_t err;
    err = paging_alloc(st, &vaddr, size, alignment);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "paging_alloc failed\n");
    }
    assert(vaddr != NULL);
    assert(((size_t) vaddr & (alignment - 1U)) == 0);

    if (!no_print) {
        DEBUG_PRINTF("paging_alloc to %p/%lu success\n", vaddr, size);
    }

    if (unmap) {
        err = paging_unmap(st, (void *)vaddr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_unmap failed\n");
        }
        if (!no_print) {
            DEBUG_PRINTF("unmap %p/%lu success\n", vaddr, size);
        }
    }
}

static void paging_force_refill(struct paging_state *st)
{
    st->region_slabs.refill_func(&st->region_slabs);
    st->vnode_slabs.refill_func(&st->vnode_slabs);
}

void grading_test_paging(struct mm *mm, struct paging_state *st)
{
    DEBUG_PRINTF("Start grading_test_paging...\n");

    DEBUG_PRINTF("[Try Fixed Mapping]\n");
    paging_force_refill(st);  // avoid pages being used by dynamic allocation
    const uint64_t vaddr_base = VMSAv8_64_L0_SIZE << 4;  // avoid conflict with slab allocators
    test_fixed_mapping_success(mm, st, vaddr_base, BASE_PAGE_SIZE, false,
                               UNMAP_FOR_ALL_TEST);
    test_fixed_mapping_success(mm, st, vaddr_base + BASE_PAGE_SIZE, BASE_PAGE_SIZE, false,
                               UNMAP_FOR_ALL_TEST);
    test_fixed_mapping_success(mm, st, vaddr_base + 4 * BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                               false, UNMAP_FOR_ALL_TEST);
    test_fixed_mapping_success(mm, st, vaddr_base + 2 * BASE_PAGE_SIZE,
                               BASE_PAGE_SIZE * 2, false, UNMAP_FOR_ALL_TEST);
    test_fixed_mapping_success(mm, st, vaddr_base + 5 * BASE_PAGE_SIZE,
                               BASE_PAGE_SIZE * 4, false, UNMAP_FOR_ALL_TEST);
    test_fixed_mapping_success(mm, st, vaddr_base + VMSAv8_64_L0_SIZE,
                               BASE_PAGE_SIZE * 2048, false, UNMAP_FOR_ALL_TEST);

    DEBUG_PRINTF("[Try Overlapping Fixed Mapping]\n");
    const uint64_t vaddr_base2 = vaddr_base + VMSAv8_64_L0_SIZE * 2;
    paging_force_refill(st);  // avoid pages being used by dynamic allocation
    test_fixed_mapping_success(mm, st, vaddr_base2, BASE_PAGE_SIZE, false,
                               UNMAP_FOR_ALL_TEST);  // one page in first L3
    test_fixed_mapping_success(
        mm, st, vaddr_base2 + VMSAv8_64_L2_BLOCK_SIZE * 4 - BASE_PAGE_SIZE,
        BASE_PAGE_SIZE, false, UNMAP_FOR_ALL_TEST);  // one page in the 4th L3
    test_fixed_mapping_success(
        mm, st, vaddr_base2 + BASE_PAGE_SIZE,
        VMSAv8_64_L2_BLOCK_SIZE * 4 - BASE_PAGE_SIZE * 2, false,
        UNMAP_FOR_ALL_TEST);  // involves 4 L3's, including the two above

    const uint64_t vaddr_base3 = vaddr_base2 + VMSAv8_64_L0_SIZE;
    paging_force_refill(st);  // avoid pages being used by dynamic allocation
    test_fixed_mapping_success(mm, st, vaddr_base3, BASE_PAGE_SIZE, false,
                               UNMAP_FOR_ALL_TEST);  // one page in first L3
    test_fixed_mapping_success(
        mm, st, vaddr_base3 + VMSAv8_64_L2_BLOCK_SIZE - BASE_PAGE_SIZE, BASE_PAGE_SIZE,
        false, UNMAP_FOR_ALL_TEST);  // one page in the 2nd L3
    test_fixed_mapping_success(
        mm, st, vaddr_base3 + BASE_PAGE_SIZE, VMSAv8_64_L2_BLOCK_SIZE - BASE_PAGE_SIZE * 2,
        false, UNMAP_FOR_ALL_TEST);  // involves 2 L3's, including the two above

    DEBUG_PRINTF("[Try Dynamic Mapping]\n");
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, UNMAP_FOR_ALL_TEST);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, UNMAP_FOR_ALL_TEST);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, UNMAP_FOR_ALL_TEST);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 2, false, UNMAP_FOR_ALL_TEST);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 4, false, UNMAP_FOR_ALL_TEST);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 2048, false, UNMAP_FOR_ALL_TEST);

    DEBUG_PRINTF("[Try Alloc + Fixed Mapping]\n");
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE, false,
                                          UNMAP_FOR_ALL_TEST);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE, false,
                                          UNMAP_FOR_ALL_TEST);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE, false,
                                          UNMAP_FOR_ALL_TEST);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE * 2, false,
                                          UNMAP_FOR_ALL_TEST);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE * 4, false,
                                          UNMAP_FOR_ALL_TEST);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE * 2048, false,
                                          UNMAP_FOR_ALL_TEST);

    DEBUG_PRINTF("[Try Alloc + Fixed Mapping in the Middle]\n");
    void *vaddr = NULL;
    test_mapping_alloc_success(mm, st, BASE_PAGE_SIZE * 4, &vaddr, false,
                               false);
    test_fixed_mapping_success(mm, st, (size_t)vaddr + BASE_PAGE_SIZE, BASE_PAGE_SIZE,
                               false, false);
    test_fixed_mapping_success(mm, st, (size_t)vaddr + BASE_PAGE_SIZE * 2,
                               BASE_PAGE_SIZE * 2, false, false);
    test_fixed_mapping_success(mm, st, (size_t)vaddr, BASE_PAGE_SIZE, false,
                               false);

    DEBUG_PRINTF("[Try Alloc + Fixed Mapping in the Middle Large]\n");
    paging_force_refill(st);  // avoid pages being used by dynamic allocation
    test_mapping_alloc_success(mm, st, BASE_PAGE_SIZE * 2048, &vaddr, false,
                               false);
    test_fixed_mapping_success(mm, st, (size_t)vaddr + BASE_PAGE_SIZE * 1024,
                               BASE_PAGE_SIZE, false, false);
    test_fixed_mapping_success(mm, st, (size_t)vaddr + BASE_PAGE_SIZE * 1025,
                               BASE_PAGE_SIZE, false, false);

    DEBUG_PRINTF("[Try Alloc with Alignment]\n");
    test_alloc_with_alignment_success(mm, st, BASE_PAGE_SIZE, BASE_PAGE_SIZE * 2048,
                                      false, UNMAP_FOR_ALL_TEST);
    test_alloc_with_alignment_success(mm, st, BASE_PAGE_SIZE * 2048,
                                      BASE_PAGE_SIZE * 2048, false, UNMAP_FOR_ALL_TEST);
    test_alloc_with_alignment_success(mm, st, BASE_PAGE_SIZE, VMSAv8_64_L0_SIZE * 4,
                                      false, UNMAP_FOR_ALL_TEST);

    struct capref frame = test_alloc_frame_success(mm, BASE_PAGE_SIZE, false);

    // Index 0 L1 page table
    DEBUG_PRINTF("[Try Paging to Index 0 L1]\n");
    test_paging_fixed_map_fail(st, 0, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    test_paging_fixed_map_fail(st, VMSAv8_64_L0_SIZE - BASE_PAGE_SIZE, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    // In kernel space

    DEBUG_PRINTF("[Try Paging to Kernel Space Addresses]\n");
    test_paging_fixed_map_fail(st, -1, frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    test_paging_fixed_map_fail(st, BIT(48), frame, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);

    DEBUG_PRINTF("[Try Unmapping Fixed Maps]\n");
    const uint64_t vaddr_base4 = vaddr_base3 + VMSAv8_64_L0_SIZE;
    test_fixed_mapping_success(mm, st, vaddr_base4, BASE_PAGE_SIZE, false, true);
    test_fixed_mapping_success(mm, st, vaddr_base4, BASE_PAGE_SIZE, false, true);
    test_fixed_mapping_success(mm, st, vaddr_base4, BASE_PAGE_SIZE * 4, false, true);
    test_fixed_mapping_success(mm, st, vaddr_base4, BASE_PAGE_SIZE * 2048, false, true);
    test_fixed_mapping_success(mm, st, vaddr_base4, BASE_PAGE_SIZE, false, true);

    DEBUG_PRINTF("[Try Unmapping Dynamic Maps]\n");
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, true);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, true);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE, false, true);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 2, false, true);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 4, false, true);
    test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * 2048, false, true);

    DEBUG_PRINTF("[Try Unmapping Alloc + Fixed]\n");
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE, false, true);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE * 4, false, true);
    test_alloc_plus_fixed_mapping_success(mm, st, BASE_PAGE_SIZE * 2048, false, true);
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
        test_fixed_mapping_success(mm, st, vaddr_base, BASE_PAGE_SIZE * (i / 256 + 1), true,
                                   UNMAP_FOR_ALL_TEST);
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
        test_dynamic_mapping_success(mm, st, BASE_PAGE_SIZE * (i / 256 + 1), true,
                                     UNMAP_FOR_ALL_TEST);
        if (i % 100 == 0) {
            DEBUG_PRINTF("  %d times...\n", i);
        }
    }
    DEBUG_PRINTF("  %d times done\n", count);
}
