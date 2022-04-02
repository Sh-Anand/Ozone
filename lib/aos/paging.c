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

// cap is not initialized
static errval_t create_node(struct paging_state *st, size_t index, size_t count,
                            struct vnode_cap_node **ret)
{
    struct vnode_cap_node *n = slab_alloc(&st->slabs);
    if (n == NULL) {
        return MM_ERR_NEW_NODE;  // FIXME: change to paging error
    }
    n->index = index;
    n->count = count;
    n->max_continuous_count = VMSAv8_64_PTABLE_NUM_ENTRIES;
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
static errval_t upgrade_node_to_page_table(struct paging_state *st,
                                           struct vnode_cap_node *n, enum objtype type,
                                           struct capref parent_cap)
{
    assert(n != NULL);
    assert(n->count == 1);

    errval_t err;
    err = pt_alloc(st, type, &n->cap);
    if (err_is_fail(err)) {
        return err;
    }
    err = apply_mapping(st, parent_cap, n->cap, n->index,
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

    slab_init(&st->slabs, sizeof(struct vnode_cap_node), slab_default_refill);

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
    st->l0->cap = pdir;
    st->refilling = false;

    // TODO: for now just handle the only case of skipping first L1
    if (start_vaddr == VMSAv8_64_L0_SIZE) {
        struct vnode_cap_node *first_l1;
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

static void update_max_continuous_count(struct vnode_cap_node *node)
{
    if (LIST_EMPTY(&node->children)) {
        node->max_continuous_count = VMSAv8_64_PTABLE_NUM_ENTRIES;
    } else {
        struct vnode_cap_node *n;
        LIST_FOREACH(n, &node->children, link)
        {
            size_t next_index = (LIST_NEXT(n, link) == NULL ? VMSAv8_64_PTABLE_NUM_ENTRIES
                                                            : LIST_NEXT(n, link)->index);
            assert(next_index >= n->index + n->count && "paging: linked list not sorted");
            size_t empty_region = next_index - (n->index + n->count);
            if (empty_region > node->max_continuous_count) {
                node->max_continuous_count = empty_region;
            }
        }
    }
}

static size_t get_child_index(lvaddr_t vaddr, size_t level)
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
            return MM_ERR_SLOT_NOSLOTS;  // XXX: change to proper error
        }
        st->refilling = false;
        // DEBUG_PRINTF("paging: refill slabs done\n");
    }
    return SYS_ERR_OK;
}

// Forward declaration
static errval_t _map_recursive(struct paging_state *st, struct vnode_cap_node *node,
                               size_t level, lvaddr_t rvaddr, struct capref frame,
                               size_t offset, size_t bytes, uint64_t attr,
                               lvaddr_t *out_rvaddr);

// Wrapper function for _map_recursive to ensure refilling
static inline errval_t map_recursive(struct paging_state *st, struct vnode_cap_node *node,
                                     size_t level, lvaddr_t rvaddr, struct capref frame,
                                     size_t offset, size_t bytes, uint64_t attr,
                                     lvaddr_t *out_rvaddr)
{
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
 * @param rvaddr    If out_vaddr == NULL, relative address to the node. Otherwise, ignored.
 * @param frame
 * @param offset
 * @param bytes
 * @param attr
 * @param out_vaddr If not NULL, rvaddr is ignored and arbitrary placement is allowed
 * @return
 * @note Require base page alignment and size.
 * @note IMPORTANT: expect ensure_enough_slabs() before every call into this function,
 *       including recursion.
 */
static errval_t _map_recursive(struct paging_state *st, struct vnode_cap_node *node,
                               size_t level, lvaddr_t rvaddr, struct capref frame,
                               size_t offset, size_t bytes, uint64_t attr,
                               lvaddr_t *out_rvaddr)
{
    //    debug_printf("_map_recursive level = %u, rvaddr = %lx, bytes = %lu, out_rvaddr =
    //    %p\n", level, rvaddr, bytes, out_rvaddr);

    assert(level <= 3 && "paging: invalid level");
    assert(ROUND_UP(bytes, BASE_PAGE_SIZE) == bytes);
    assert(ROUND_UP(offset, BASE_PAGE_SIZE) == offset);

    if (node->max_continuous_count == 0 && LIST_EMPTY(&node->children)) {  // invalid block
        return MM_ERR_NOT_FOUND;
    }

    errval_t err;
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];

    size_t child_start_index = get_child_index(rvaddr, level);  // inclusive
    size_t child_end_index = get_child_index(ROUND_UP(rvaddr + bytes, CHILD_SIZE),
                                             level);  // exclusive
    if (child_end_index == 0)
        child_end_index = 512;
    size_t child_count = child_end_index - child_start_index;
    // debug_printf("child_start_index = %lu, end = %lu, count = %lu\n",
    // child_start_index, child_end_index, child_count);

    assert(child_end_index > child_start_index);
    assert(child_start_index < 512);
    assert(child_end_index <= 512);
    assert((child_end_index - child_start_index) * CHILD_SIZE >= bytes);

    if (child_count == 1 && level < 3 && !LIST_EMPTY(&node->children)) {
        // Find a child and try dive into it
        struct vnode_cap_node *n;
        LIST_FOREACH(n, &node->children, link)
        {
            assert(n->count == 1 && "paging: page table cannot have count > 1");
            if (out_rvaddr == NULL) {
                // Fixed mapping
                if (n->index == child_start_index) {
                    assert(rvaddr >= n->index * CHILD_SIZE);
                    err = _map_recursive(st, n, level + 1, rvaddr - n->index * CHILD_SIZE,
                                         frame, offset, bytes, attr, out_rvaddr);
                    return err;  // must be this node, return directly, either work or fail
                } else if (n->index > child_start_index) {
                    break;
                }
            } else {
                // Dynamic mapping
                err = _map_recursive(st, n, level + 1, 0 /* useless */, frame, offset,
                                     bytes, attr, out_rvaddr);
                *out_rvaddr += n->index * CHILD_SIZE;
                if (err_is_ok(err)) {
                    return SYS_ERR_OK;
                } else if (err != MM_ERR_NOT_FOUND) {  // error other than no memory
                    return err;
                }
            }
        }
    }
    // Fall back to create children at this level

    struct vnode_cap_node *n;
    struct vnode_cap_node *heading
        = NULL;  // allow fixed mapping to overlap for one at head
    bool should_update_max_continuous_count;
    if (LIST_EMPTY(&node->children)) {
        n = NULL;
        should_update_max_continuous_count = true;
    } else {
        LIST_FOREACH(n, &node->children, link)
        {
            size_t next_index = (LIST_NEXT(n, link) == NULL ? VMSAv8_64_PTABLE_NUM_ENTRIES
                                                            : LIST_NEXT(n, link)->index);
            assert(next_index >= n->index + n->count && "paging: linked list not sorted");

            size_t continuous_count = next_index - (n->index + n->count);
            // debug_printf("continuous_count = %lu, node->max_continuous_count = %lu\n",
            // continuous_count, node->max_continuous_count);
            assert(continuous_count <= node->max_continuous_count
                   && "paging: max_continuous_count too small");

            if (out_rvaddr == NULL) {  // require specific mapping
                // Allow overlapping for one at head
                // TODO: overlapping for one at the end is not allowed
                if (n->index + n->count <= child_start_index + 1
                    && next_index >= child_end_index) {
                    should_update_max_continuous_count = (continuous_count
                                                          == node->max_continuous_count);
                    if (n->index + n->count == child_start_index + 1) {
                        heading = n;
                    }
                    break;
                }
            } else {
                if (continuous_count >= child_count) {
                    should_update_max_continuous_count = (continuous_count
                                                          == node->max_continuous_count);
                    // Assign new range
                    child_start_index = n->index + n->count;
                    child_end_index = child_start_index + child_count;
                    rvaddr
                        = child_start_index
                          * CHILD_SIZE;  // the map size computation below will just work
                    break;
                }
            }
        }
        if (n == NULL) {              // memory already occupied or no slot available
            return MM_ERR_NOT_FOUND;  // XXX: change to paging error
        }
    }

    if (level < 3) {
        // Create a placeholder node to ensure refill doesn't come to this region
        struct vnode_cap_node *placeholder;

        // This should never trigger a refill since ensure_enough_slabs() is expected
        // before every call in this function
        err = create_node(st, child_start_index + (heading != NULL),
                          child_count - (heading != NULL), &placeholder);
        if (err_is_fail(err)) {
            return err;
        }

        // Insert the placeholder
        if (n == NULL) {
            LIST_INSERT_HEAD(&node->children, placeholder, link);
        } else {
            LIST_INSERT_AFTER(n, placeholder, link);  // ensure ordering
        }
        // Insert before placeholder next time and shrink placeholder
        // The placeholder will become the last node
        if (should_update_max_continuous_count) {
            update_max_continuous_count(node);
        }

        // Any refill starting from here should be OK

        // Construct nodes
        for (size_t i = child_start_index; i < child_end_index; i++) {
            struct vnode_cap_node *new_node;

            if (heading != NULL) {
                new_node = heading;
                heading = NULL;

            } else {
                if (placeholder->count == 1) {
                    new_node = placeholder;
                } else {
                    err = create_node(st, i, 1, &new_node);
                    if (err_is_fail(err)) {
                        return err;
                    }
                    placeholder->index++;
                    placeholder->count--;
                    LIST_INSERT_BEFORE(placeholder, new_node, link);
                }
                assert(new_node != NULL);

                // Create a page table and map
                err = upgrade_node_to_page_table(st, new_node,
                                                 CHILD_PAGE_TABLE_TYPE[level], node->cap);
                if (err_is_fail(err)) {
                    return err;
                }
            }

            // Relative to this node
            lvaddr_t child_start_vaddr = i * CHILD_SIZE;
            if (child_start_vaddr < rvaddr) {
                child_start_vaddr = rvaddr;
            }

            lvaddr_t child_end_vaddr = (i + 1) * CHILD_SIZE;  // exclusive
            if (child_end_vaddr > rvaddr + bytes) {
                child_end_vaddr = rvaddr + bytes;
            }

            size_t child_mapping_size = child_end_vaddr - child_start_vaddr;

            // Must call ensure_enough_slabs before recursion
            err = ensure_enough_slabs(st);
            if (err_is_fail(err)) {
                return err;
            }

            lvaddr_t next_rvaddr = child_start_vaddr - (i * CHILD_SIZE);
            if (out_rvaddr != NULL) {
                assert(next_rvaddr == 0);
            }

            // Call the wrapper to ensure_enough_slabs before recursion
            err = map_recursive(st, new_node, level + 1, next_rvaddr, frame, offset,
                                child_mapping_size, attr, out_rvaddr);
            offset += child_mapping_size;
            if (err_is_fail(err)) {
                return err;
            }
        }
        assert(placeholder->count == 1);

        if (out_rvaddr) {
            *out_rvaddr += child_start_index * CHILD_SIZE;
        }

    } else {  // level == 3

        struct vnode_cap_node *new_node;
        // This should never trigger a refill since ensure_enough_slabs() is expected
        // before every call in this function
        err = create_node(st, child_start_index, child_count, &new_node);
        if (err_is_fail(err)) {
            return err;
        }

        // Insert the node
        if (n == NULL) {
            LIST_INSERT_HEAD(&node->children, new_node, link);
        } else {
            LIST_INSERT_AFTER(n, new_node, link);  // ensure ordering
        }
        if (should_update_max_continuous_count) {
            update_max_continuous_count(node);
        }

        // Any refill starting from here should be OK

        // Apply mapping all at once
        err = apply_mapping(st, node->cap, frame, child_start_index, attr, offset,
                            child_count);
        if (err_is_fail(err)) {
            return err;
        }

        if (out_rvaddr) {
            *out_rvaddr = child_start_index * CHILD_SIZE;
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
    /**
     * TODO(M2): Implement this function
     *   - Find a region of free virtual address space that is large enough to
     *     accomodate a buffer of size `bytes`.
     */
    *buf = NULL;

    return LIB_ERR_NOT_IMPLEMENTED;
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
    // TODO: allocated nodes and slots are not freed on failure return

    assert(st->l0 != NULL);

    if (bytes >= VMSAv8_64_L0_SIZE
                     * VMSAv8_64_PTABLE_NUM_ENTRIES) {  // trying to map into kernel
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

    return _map_recursive(st, st->l0, 0, 0, frame, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
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
    // TODO: allocated nodes and slots are not freed on failure return

    assert(st->l0 != NULL);

    if (vaddr >= VMSAv8_64_L0_SIZE * VMSAv8_64_PTABLE_NUM_ENTRIES /* plus can overflow */
        || vaddr + bytes
               >= VMSAv8_64_L0_SIZE
                      * VMSAv8_64_PTABLE_NUM_ENTRIES) {  // map into kernel address space
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

    return _map_recursive(st, st->l0, 0, vaddr, frame, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
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
