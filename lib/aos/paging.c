/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

static const size_t CHILD_BLOCK_SIZE[] = { VMSAv8_64_L0_SIZE, VMSAv8_64_L1_BLOCK_SIZE,
                                           VMSAv8_64_L2_BLOCK_SIZE,
                                           VMSAv8_64_BASE_PAGE_SIZE };
static const size_t CHILD_PAGE_TABLE_TYPE[]
    = { ObjType_VNode_AARCH64_l1, ObjType_VNode_AARCH64_l2, ObjType_VNode_AARCH64_l3 };

static struct paging_state current;

#define SLAB_INIT_BUF_SIZE 8192
static char slab_buf[SLAB_INIT_BUF_SIZE];
static bool slab_buf_used = false;

#define SLAB_REFILL_THRESHOLD 12

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state *st, enum objtype type, struct capref *ret)
{
    errval_t err;
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}

// Create a node. cap is initialized to NULL_CAP. link is not initialized
static errval_t create_node(struct paging_state *st, size_t index, size_t count,
                            struct paging_node **ret)
{
    struct paging_node *n = slab_alloc(&st->slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    n->index = index;
    n->count = count;
    n->max_continuous_count = VMSAv8_64_PTABLE_NUM_ENTRIES;
    n->vnode_cap = NULL_CAP;
    LIST_INIT(&n->children);
    *ret = n;
    return SYS_ERR_OK;
}

// May call back to mm and paging due to slot refill
static errval_t apply_mapping(struct paging_state *st, struct capref dest,
                              struct capref src, capaddr_t slot, uint64_t attr,
                              uint64_t off, uint64_t pte_count)
{
    errval_t err;

    // Allocate the mapping capability slot
    struct capref mapping_cap;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping_cap);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed for mapping_cap: %s\n", err_getstring(err));
        return err;
    }

    // Apply the mapping
    err = vnode_map(dest, src, slot, attr, off, pte_count, mapping_cap);
    if (err_is_fail(err)) {
        return err;
    }

    // XXX: discard mapping_cap for now
    return SYS_ERR_OK;
}

// Not inserted into parent
static errval_t upgrade_node_to_page_table(struct paging_state *st, struct paging_node *n,
                                           enum objtype type, struct capref parent_cap)
{
    assert(n != NULL);
    assert(n->count == 1);

    errval_t err;
    err = pt_alloc(st, type, &n->vnode_cap);
    if (err_is_fail(err)) {
        return err;
    }
    err = apply_mapping(st, parent_cap, n->vnode_cap, n->index,
                        KPI_PAGING_FLAGS_READ | KPI_PAGING_FLAGS_WRITE, 0, 1);
    if (err_is_fail(err)) {
        return err;
    }
    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.

    assert(ca != NULL);

    st->slot_alloc = ca;

    slab_init(&st->slabs, sizeof(struct paging_node), slab_default_refill);

    if (!slab_buf_used) {
        // Paging is not setup yet so refill is not available
        slab_grow(&st->slabs, slab_buf, SLAB_INIT_BUF_SIZE);
        slab_buf_used = true;
    }

    // Create L0 node
    errval_t err;
    err = create_node(st, 0, 1, &st->l0);
    if (err_is_fail(err)) {
        return err;
    }
    st->l0->vnode_cap = pdir;
    st->refilling = false;

    // TODO: for now just handle the only case of skipping first L1
    if (start_vaddr == VMSAv8_64_L0_SIZE) {
        struct paging_node *first_l1;
        err = create_node(st, 0, 1, &first_l1);
        if (err_is_fail(err)) {
            return err;
        }
        first_l1->max_continuous_count = 0;  // invalid
        assert(LIST_EMPTY(&first_l1->children));

        LIST_INSERT_HEAD(&st->l0->children, first_l1, link);
        st->l0->max_continuous_count--;
    }

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return paging_init_state(st, start_vaddr, pdir, ca);
}

/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");
    // TODO (M2): Call paging_init_state for &current
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.

    errval_t err;
    err = paging_init_state(&current, VMSAv8_64_L0_SIZE, cap_vroot,
                            get_default_slot_allocator());
    if (err_is_fail(err)) {
        return err;
    }

    set_current_paging_state(&current);
    return SYS_ERR_OK;
}


/**
 * @brief Initializes the paging functionality for the calling thread
 *
 * @param[in] t   the tread to initialize the paging state for.
 *
 * This function prepares the thread to handing its own page faults
 */
errval_t paging_init_onthread(struct thread *t)
{
    // TODO (M4):
    //   - setup exception handler for thread `t'.
    return LIB_ERR_NOT_IMPLEMENTED;
}

static void update_max_continuous_count(struct paging_node *node)
{
    if (LIST_EMPTY(&node->children)) {
        node->max_continuous_count = VMSAv8_64_PTABLE_NUM_ENTRIES;
    } else {
        node->max_continuous_count = 0;
        struct paging_node *n = NULL;
        do {
            struct paging_node *next_n = (n ? LIST_NEXT(n, link)
                                            : LIST_FIRST(&node->children));
            size_t region_start = (n ? n->index + n->count : 0);
            size_t region_end = (next_n ? next_n->index : VMSAv8_64_PTABLE_NUM_ENTRIES);
            assert(region_end >= region_start && "paging: linked list not sorted");
            size_t region_size = region_end - region_start;
            if (region_size > node->max_continuous_count) {
                node->max_continuous_count = region_size;
            }

            n = next_n;
        } while (n != NULL);
    }
}

static inline size_t get_child_index(lvaddr_t vaddr, size_t level)
{
    switch (level) {
    case 0:
        return VMSAv8_64_L0_INDEX(vaddr);
    case 1:
        return VMSAv8_64_L1_INDEX(vaddr);
    case 2:
        return VMSAv8_64_L2_INDEX(vaddr);
    case 3:
        return VMSAv8_64_L3_INDEX(vaddr);
    default:
        assert(!"paging: invalid level");
    }
}

static errval_t ensure_enough_slabs(struct paging_state *st)
{
    if (!st->refilling && slab_freecount(&st->slabs) < SLAB_REFILL_THRESHOLD) {
        // DEBUG_PRINTF("paging: refill slabs\n");
        st->refilling = true;
        errval_t err = st->slabs.refill_func(&st->slabs);
        if (err_is_fail(err)) {
            return err;
        } else if (slab_freecount(&st->slabs) < SLAB_REFILL_THRESHOLD) {
            return LIB_ERR_SLAB_REFILL;
        }
        st->refilling = false;
        // DEBUG_PRINTF("paging: refill slabs done\n");
    }
    return SYS_ERR_OK;
}

// An invalid node (such as placeholder to enforce start address)
static inline bool is_invalid_node(const struct paging_node *node)
{
    return node->max_continuous_count == 0 && LIST_EMPTY(&node->children);
}

// A placeholder node (such as placeholder to enforce start address)
static inline bool is_placeholder_node(const struct paging_node *node)
{
    return !is_invalid_node(node) && capref_is_null(node->vnode_cap);
}

static inline void decode_indices(size_t level, lvaddr_t rvaddr, size_t bytes,
                                  size_t *ret_inclusive_start, size_t *ret_exclusive_end,
                                  size_t *ret_count)
{
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];

    size_t child_start_index = get_child_index(rvaddr, level);  // inclusive
    size_t child_end_index = get_child_index(ROUND_UP(rvaddr + bytes, CHILD_SIZE),
                                             level);  // exclusive
    if (child_end_index == 0) {                       // wrap around
        child_end_index = 512;
    }

    assert(child_end_index > child_start_index);
    assert(child_start_index < 512);
    assert(child_end_index <= 512);
    assert((child_end_index - child_start_index) * CHILD_SIZE >= bytes);

    *ret_inclusive_start = child_start_index;
    *ret_exclusive_end = child_end_index;
    *ret_count = child_end_index - child_start_index;
}

/**
 * Chop down a node.
 * @param st
 * @param n                 The node to be chopped down.
 * @param child_start_index Inclusive.
 * @param child_end_index   Exclusive.
 * @param chop_down_to_one  If true, chop down to size of 1.
 * @param ret_start         Fill with the resulting start node in the linked list
 * @note Refill can happen inside this function. But it's guaranteed that all space
 *       occupied by the original node is still occupied at any refill.
 * @return
 */
static inline errval_t chop_down_node(struct paging_state *st, struct paging_node *n,
                                      size_t child_start_index, size_t child_end_index,
                                      bool chop_down_to_one,
                                      struct paging_node **ret_start)
{
    assert(n != NULL);
    assert(child_start_index <= child_end_index);
    assert(n->index <= child_start_index);
    assert(n->count > 0);
    assert(n->index + n->count >= child_end_index);

    errval_t err;

    // Chop the part before away
    if (n->index < child_start_index) {
        struct paging_node *node_before;
        err = create_node(st, n->index, child_start_index - n->index, &node_before);
        if (err_is_fail(err)) {
            return err;
        }
        n->index += node_before->count;
        n->count -= node_before->count;
        LIST_INSERT_BEFORE(n, node_before, link);
    }
    assert(n->index == child_start_index);

    // Chop the part after away
    if (n->index + n->count > child_end_index) {
        struct paging_node *node_after;
        err = create_node(st, child_end_index, n->index + n->count - child_end_index,
                          &node_after);
        if (err_is_fail(err)) {
            return err;
        }
        n->count -= node_after->count;
        LIST_INSERT_AFTER(n, node_after, link);
    }
    assert(n->index + n->count == child_end_index);

    if (chop_down_to_one && n->count > 1) {
        for (int i = (int)child_end_index - 1; i > (int)child_start_index; i--) {
            struct paging_node *node_after;
            err = create_node(st, i, 1, &node_after);
            if (err_is_fail(err)) {
                return err;
            }
            n->count--;
            LIST_INSERT_AFTER(n, node_after, link);
        }
        assert(n->count == 1);  // for the last iteration
    }

    assert(n->index == child_start_index);
    *ret_start = n;
    return SYS_ERR_OK;
}

/**
 * Create a node (chopped down to size one upon request, insert it to the linked list, and
 * update max_continuous_count upon request.
 * @param st
 * @param index
 * @param count
 * @param node
 * @param insert_after  If null, insert to head of node->children
 * @param ret_node
 * @param should_update_max_continuous_count
 * @param chop_down_to_one
 * @note Refill can happen inside this function. Before calling this function, the caller
 *       must guarantee that one slab can be allocated without triggering refill. And
 *       then this function guarantees that no refill can comes to the created region.
 * @return
 */
static inline errval_t create_node_and_insert(struct paging_state *st, size_t index,
                                              size_t count, struct paging_node *node,
                                              struct paging_node *insert_after,
                                              struct paging_node **ret_node,
                                              bool should_update_max_continuous_count,
                                              bool chop_down_to_one)
{
    struct paging_node *new_node;

    // Create a placeholder node to ensure refill doesn't come to this region

    // This should never trigger a refill since ensure_enough_slabs() is expected
    // before every call in this function
    errval_t err = create_node(st, index, count, &new_node);
    if (err_is_fail(err)) {
        return err;
    }
    if (insert_after == NULL) {
        LIST_INSERT_HEAD(&node->children, new_node, link);
    } else {
        LIST_INSERT_AFTER(insert_after, new_node, link);  // ensure ordering
    }
    if (should_update_max_continuous_count) {
        update_max_continuous_count(node);
    }

    // ======== Any refill starting from this point should be OK ========

    if (chop_down_to_one && new_node->count > 1) {
        err = chop_down_node(st, new_node, index, index + count, true, &new_node);
        if (err_is_fail(err)) {
            return err;
        }
    }

    *ret_node = new_node;
    return SYS_ERR_OK;
}

static inline bool unit_placeholders_matched(const struct paging_node *n,
                                             size_t child_start, size_t child_end)
{
    for (size_t i = child_start; i < child_end; i++) {
        if (n == NULL || n->index != i || !is_placeholder_node(n)) {
            return false;
        }
        assert(n->count == 1);
        n = LIST_NEXT(n, link);
    }
    return true;
}

static inline bool bulk_placeholder_matched(const struct paging_node *n,
                                            size_t child_start, size_t child_end)
{
    return n->index <= child_start && n->index + n->count >= child_end
           && is_placeholder_node(n);
}

#ifndef min
#    define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#    define max(a, b) ((a) > (b) ? (a) : (b))
#endif

// Forward declaration
static errval_t _map_recursive(struct paging_state *st, struct paging_node *node,
                               size_t level, lvaddr_t rvaddr, struct capref frame,
                               size_t offset, size_t bytes, uint64_t attr,
                               lvaddr_t *out_rvaddr);

// Wrapper function for _map_recursive to ensure refilling
static inline errval_t map_recursive(struct paging_state *st, struct paging_node *node,
                                     size_t level, lvaddr_t rvaddr, struct capref frame,
                                     size_t offset, size_t bytes, uint64_t attr,
                                     lvaddr_t *out_rvaddr)
{
    assert(st->l0 != NULL);

    if (rvaddr >= VMSAv8_64_L0_SIZE * VMSAv8_64_PTABLE_NUM_ENTRIES /* plus can overflow */
        || rvaddr + bytes >= VMSAv8_64_L0_SIZE * VMSAv8_64_PTABLE_NUM_ENTRIES) {
        // Map into kernel address space
        return MM_ERR_NOT_FOUND;
    }
    if (bytes == 0) {
        return SYS_ERR_OK;
    }

    // Must call ensure_enough_slabs before recursion
    errval_t err = ensure_enough_slabs(st);
    if (err_is_fail(err)) {
        return err;
    }
    return _map_recursive(st, node, level, rvaddr, frame, offset, bytes, attr, out_rvaddr);
}

/**
 * General recursive function for multi-level mapping. DO NOT call this function directly
 * but map_recursive() above, since some refilling must be guaranteed.
 * @param st
 * @param node
 * @param level
 * @param rvaddr    If out_vaddr == NULL, relative address to node. Otherwise, ignored.
 * @param frame     If NULL_CAP, create placeholders and attr is ignored
 * @param offset
 * @param bytes
 * @param attr      If frame != NULL_CAP, mapping attribute. Otherwise, ignored.
 * @param out_vaddr If not NULL, rvaddr is ignored and arbitrary placement is allowed.
 * @return
 * @note Require base page alignment and size.
 * @note IMPORTANT: expect ensure_enough_slabs() before every call into this function,
 *       including recursion.
 * @todo Allocated nodes and slots are not freed on failure return.
 */
static errval_t _map_recursive(struct paging_state *st, struct paging_node *node,
                               size_t level, lvaddr_t rvaddr, struct capref frame,
                               size_t offset, size_t bytes, uint64_t attr,
                               lvaddr_t *out_rvaddr)
{
    assert(level <= 3 && "paging: invalid level");
    assert(ROUND_UP(bytes, BASE_PAGE_SIZE) == bytes);
    assert(ROUND_UP(offset, BASE_PAGE_SIZE) == offset);

    if (is_invalid_node(node)) {
        return LIB_ERR_PAGING_INVALID_REGION;
    }

    errval_t err;
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];
    const bool is_fixed_mapping = (out_rvaddr == NULL);
    const bool is_allocating_placeholder = (capref_is_null(frame));
#if 0
    debug_printf("_map_recursive(%lu), node=%lu->%lu, 0x%lx/%lu  %s%s\n", level,
                 node->index, node->count, rvaddr, bytes,
                 is_fixed_mapping ? "fixed " : "dynamic ",
                 is_allocating_placeholder ? "placeholder " : "");
#endif

    size_t child_start, child_end, child_count;
    decode_indices(level, rvaddr, bytes, &child_start, &child_end, &child_count);
#if 0
    debug_printf("child_start = %lu, end = %lu, count = %lu\n", child_start, child_end, child_count);
#endif

    if (child_count == 1 && level < 3 && !LIST_EMPTY(&node->children)) {
        // Bounded in one child, find a child and try dive into it

        struct paging_node *n = NULL;
        LIST_FOREACH(n, &node->children, link)
        {
            assert(n->count == 1 && "paging: page table cannot have count > 1");

            if (is_fixed_mapping) {
                // Fixed mapping

                if (n->index == child_start) {
                    assert(rvaddr >= n->index * CHILD_SIZE);

                    if (is_placeholder_node(n)) {
                        // Create a page table and install
                        err = upgrade_node_to_page_table(
                            st, n, CHILD_PAGE_TABLE_TYPE[level], node->vnode_cap);
                        if (err_is_fail(err)) {
                            return err;
                        }
                        assert(!capref_is_null(n->vnode_cap));
                    }

                    // Here _map_recursive is called since no slab alloc has happened
                    err = _map_recursive(st, n, level + 1, rvaddr - n->index * CHILD_SIZE,
                                         frame, offset, bytes, attr, out_rvaddr);
                    return err;  // must be this node, return directly, either work or fail
                } else if (n->index > child_start) {
                    break;
                }

            } else {
                // Dynamic mapping

                if (!is_placeholder_node(n) && !is_invalid_node(n)) {
                    if (level + 1 == 3 && n->max_continuous_count == 0) {
                        // Fast path to skip full L3 tables
                    } else {
                        // Here _map_recursive is called since no slab alloc has happened
                        err = _map_recursive(st, n, level + 1, 0 /* useless */, frame,
                                             offset, bytes, attr, out_rvaddr);
                        assert(out_rvaddr != NULL);
                        *out_rvaddr += n->index * CHILD_SIZE;
                        if (err_is_ok(err)) {
                            return SYS_ERR_OK;
                        } else if (err
                                   != MM_ERR_NOT_FOUND) {  // error other than no memory
                            return err;
                        }
                    }
                }
            }
        }
    }
    // Fall back to create children at this level
    // For fixed mapping, child count must be > 1 (otherwise returned above)
    // For dynamic mapping, child count >= 1

    struct paging_node *new_node = NULL;

    struct paging_node *n = NULL;
    do {
        struct paging_node *next_n = (n ? LIST_NEXT(n, link)
                                        : LIST_FIRST(&node->children));
        size_t region_start = (n ? n->index + n->count : 0);
        size_t region_end = (next_n ? next_n->index : VMSAv8_64_PTABLE_NUM_ENTRIES);
        assert(region_end >= region_start && "paging: linked list not sorted");
        size_t region_size = region_end - region_start;
#if 0
        debug_printf("region_size = %lu, node->max_continuous_count = %lu\n", region_size, node->max_continuous_count);
#endif
        assert(region_size <= node->max_continuous_count
               && "paging: max_continuous_count too small");

        if (is_fixed_mapping) {
            // Fixed mapping
#if 0
                debug_printf("relaxed_start = %lu, relaxed_end = %lu\n", relaxed_start, relaxed_end);
#endif
            // Use placeholder
            if (n != NULL && is_placeholder_node(n)) {
                if (level < 3) {  // unit placeholder
                    if (unit_placeholders_matched(n, child_start, child_end)) {
                        new_node = n;
                        break;
                    }
                } else {
                    if (bulk_placeholder_matched(n, child_start, child_end)) {
                        // Safe to call because the space is already occupied
                        err = chop_down_node(st, n, child_start, child_end, false,
                                             &new_node);
                        if (err_is_fail(err)) {
                            return err;
                        }
                        assert(new_node != NULL);
                        break;
                    }
                }
            }

            // Use empty region between current node and the next
            // Allow overlapping for one at the front and one at the end
            size_t relaxed_start = (n ? n->index + n->count - 1 : 0);
            size_t relaxed_end = (next_n ? next_n->index + 1
                                         : VMSAv8_64_PTABLE_NUM_ENTRIES);
            if ((level < 3 && relaxed_start <= child_start && relaxed_end >= child_end)
                || (level == 3 && region_start <= child_start && region_end >= child_end)) {
#if 0
                debug_printf("relaxed_start = %lu, relaxed_end = %lu IN\n", relaxed_start, relaxed_end);
#endif
                size_t create_start = max(child_start, region_start);
                size_t create_end = min(child_end, region_end);
                if (create_end > create_start) {
                    size_t create_size = create_end - create_start;
                    // Safe to call this function since ensure_enough_slabs() is
                    // expected before every call in the current function
                    err = create_node_and_insert(
                        st, create_start, create_size, node, n, &new_node,
                        (region_size == node->max_continuous_count), (level < 3));
                    if (err_is_fail(err)) {
                        return err;
                    }
                    if (create_start != child_start) {
                        assert(n != NULL);
                        new_node = n;
                    }
                } else {
                    assert(n != NULL);
                    new_node = n;
                }
                break;
            }
        } else {
            // Dynamic mapping

            if (region_size >= child_count) {  // find a region large enough

                // Assign new indices
                child_start = region_start;
                child_end = child_start + child_count;
                rvaddr = child_start * CHILD_SIZE;
                // The map size computation below will just work

                // Safe to call this function since ensure_enough_slabs() is expected
                // before every call in the current function
                err = create_node_and_insert(
                    st, child_start, child_count, node, n, &new_node,
                    (region_size == node->max_continuous_count), (level < 3));
                if (err_is_fail(err)) {
                    return err;
                }
                break;
            }
        }

        n = next_n;
    } while (n != NULL);

    if (new_node == NULL) {       // memory already occupied or no slot available
        return MM_ERR_NOT_FOUND;  // XXX: change to paging error
    }

    assert(new_node != NULL);
#if 0
    debug_printf("new_node->index = %lu, count = %lu, is_placeholder_node = %d\n",
                 new_node->index, new_node->count, is_placeholder_node(new_node));
#endif
    assert(new_node->index == child_start);

    if (level < 3) {
        for (size_t i = child_start; i < child_end; i++) {
            assert(new_node->index == i);
            assert(new_node->count == 1);

            // Relative to this node
            lvaddr_t child_start_vaddr = max(i * CHILD_SIZE, rvaddr);
            lvaddr_t child_end_vaddr = min((i + 1) * CHILD_SIZE, rvaddr + bytes);
            size_t child_mapping_size = child_end_vaddr - child_start_vaddr;
            assert(child_mapping_size <= CHILD_SIZE);

            lvaddr_t next_rvaddr = child_start_vaddr - (i * CHILD_SIZE);
            if (!is_fixed_mapping) {
                // Dynamic mapping, align to the left
                assert(next_rvaddr == 0);
            }

            if (!is_allocating_placeholder
                || (child_count == 1 && child_mapping_size < CHILD_SIZE)) {
                if (is_placeholder_node(new_node)) {
                    // Create a page table and install
                    // Put here for unified handling of new node and empty node
                    err = upgrade_node_to_page_table(
                        st, new_node, CHILD_PAGE_TABLE_TYPE[level], node->vnode_cap);
                    if (err_is_fail(err)) {
                        return err;
                    }
                    assert(!capref_is_null(new_node->vnode_cap));
                }

                // Call the wrapper to ensure_enough_slabs before recursion
                assert(!capref_is_null(new_node->vnode_cap));
                err = map_recursive(st, new_node, level + 1, next_rvaddr, frame, offset,
                                    child_mapping_size, attr,
                                    /* only continue to be dynamic if one child  */
                                    /* if fixed, out_rvaddr == NULL */
                                    (child_count == 1 ? out_rvaddr : NULL));
                if (err_is_fail(err)) {
                    return err;
                }

            } else {  // is_allocating_placeholder && (spanning || exact match)

                assert(is_placeholder_node(new_node));
                if (out_rvaddr) {
                    assert(next_rvaddr == 0);
                    *out_rvaddr = next_rvaddr;
                }
            }
            offset += child_mapping_size;

            new_node = LIST_NEXT(new_node, link);
        }

        if (out_rvaddr) {
            if (child_count > 1) {  // become fixed and not passed to the next level
                *out_rvaddr = 0;
            }
            *out_rvaddr += child_start * CHILD_SIZE;
        }

    } else {  // level == 3

        assert(new_node->index == child_start && new_node->count == child_count);

        if (!is_allocating_placeholder) {
            // Actually apply the mapping, all at once

            err = apply_mapping(st, node->vnode_cap, frame, child_start, attr, offset,
                                child_count);
            if (err_is_fail(err)) {
                return err;
            }
        }

        if (out_rvaddr) {
            *out_rvaddr = child_start * CHILD_SIZE;
        }
    }

    // if (out_rvaddr) debug_printf("level %lu out_rvaddr = %lu\n", level, *out_rvaddr);

    return SYS_ERR_OK;
}

static uint64_t flags_to_attr(int flags)
{
    uint64_t attr = 0;
    if (flags & VREGION_FLAGS_READ)
        attr |= KPI_PAGING_FLAGS_READ;
    if (flags & VREGION_FLAGS_WRITE)
        attr |= KPI_PAGING_FLAGS_WRITE;
    if (flags & VREGION_FLAGS_EXECUTE)
        attr |= KPI_PAGING_FLAGS_EXECUTE;
    if (flags & VREGION_FLAGS_NOCACHE)
        attr |= KPI_PAGING_FLAGS_NOCACHE;
    return attr;
}


/**
 * @brief Find a free region of virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    // TODO: support alignment
    if (st == NULL) {
        return ERR_INVALID_ARGS;
    }
    return map_recursive(st, st->l0, 0, 0, NULL_CAP, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
                         0, (lvaddr_t *)buf);
}


/**
 * \brief Finds a free virtual address and maps `bytes` of the supplied frame at that address
 *
 * @param[in]  st      the paging state to create the mapping in
 * @param[out] buf     returns the virtual address at which this frame has been mapped.
 * @param[in]  bytes   the number of bytes to map.
 * @param[in]  frame   the frame capability to be mapped
 * @param[in]  flags   The flags that are to be set for the newly mapped region,
 *                     see 'paging_flags_t' in paging_types.h .
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags)
{
    if (st == NULL) {
        return ERR_INVALID_ARGS;
    }
    return map_recursive(st, st->l0, 0, 0, frame, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
                         flags_to_attr(flags), (lvaddr_t *)buf);
}


/**
 * @brief mapps the provided frame at the supplied address in the paging state
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] vaddr   the virtual address to create the mapping at
 * @param[in] frame   the frame to map in
 * @param[in] bytes   the number of bytes that will be mapped.
 * @param[in] flags   The flags that are to be set for the newly mapped region,
 *                    see 'paging_flags_t' in paging_types.h .
 *
 * @return SYS_ERR_OK on success.
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    if (st == NULL) {
        return ERR_INVALID_ARGS;
    }
    return map_recursive(st, st->l0, 0, vaddr, frame, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
                         flags_to_attr(flags), NULL);
}


/**
 * @brief Unmaps the region starting at the supplied pointer.
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] region  starting address of the region to unmap
 *
 * @return SYS_ERR_OK on success, or error code indicating the kind of failure
 *
 * The supplied `region` must be the start of a previously mapped frame.
 *
 * @NOTE: Implementing this function is optional.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}
