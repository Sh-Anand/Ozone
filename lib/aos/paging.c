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

// #define DEBUG_REFILL

static const lvaddr_t TABLE_ADDR_MASK[] = { MASK(PAGING_ADDR_BITS), VMSAv8_64_L0_MASK,
                                            VMSAv8_64_L1_BLOCK_MASK,
                                            VMSAv8_64_L2_BLOCK_MASK,
                                            VMSAv8_64_BASE_PAGE_MASK };

static const size_t CHILD_BLOCK_SIZE[] = { VMSAv8_64_L0_SIZE, VMSAv8_64_L1_BLOCK_SIZE,
                                           VMSAv8_64_L2_BLOCK_SIZE,
                                           VMSAv8_64_BASE_PAGE_SIZE };

static const size_t PAGE_TABLE_TYPE[] = { ObjType_VNode_AARCH64_l0,
                                          ObjType_VNode_AARCH64_l1,
                                          ObjType_VNode_AARCH64_l2,
                                          ObjType_VNode_AARCH64_l3 };

static struct paging_state current;

// For growing the slab allocator at first
#define SLAB_INIT_BUF_SIZE 4096
static char slab_buf[4][SLAB_INIT_BUF_SIZE];
static bool slab_buf_used = false;

#define REGION_SLAB_REFILL_THRESHOLD (PAGING_ADDR_BITS - BASE_PAGE_BITS)
#define VNODE_SLAB_REFILL_THRESHOLD 8
#define MAPPING_NODE_SLAB_REFILL_THRESHOLD 8
#define MAPPING_CHILD_SLAB_REFILL_THRESHOLD 8

// Forward declarations
static void page_fault_handler(enum exception_type type, int subtype, void *addr,
                               arch_registers_state_t *regs);
static errval_t set_page_fault_handler(void);

#define EXCEPTION_STACK_SIZE (BASE_PAGE_SIZE * 4)
static char exception_stack[EXCEPTION_STACK_SIZE];

#ifndef min
#    define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#    define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#define CRITICAL_SECTION_ENTER                                                           \
    /*THREAD_MUTEX_ENTER(&st->frame_alloc_mutex)                                         \
    {                                                                                    \
        dispatcher_handle_t handle = disp_disable();                                     \
        do*/

#define CRITICAL_SECTION_EXIT                                                            \
    /*while (0)                                                                          \
        ;                                                                                \
    disp_enable(handle);                                                                 \
    }                                                                                    \
    THREAD_MUTEX_EXIT(&st->frame_alloc_mutex)*/

/// RB tree implementations for general nodes and wrapper functions

static int paging_rb_tree_node_cmp(struct paging_rb_tree_node *e1,
                                   struct paging_rb_tree_node *e2)
{
    return (e1->addr < e2->addr ? -1 : e1->addr > e2->addr);
}

RB_PROTOTYPE(paging_rb_tree, paging_rb_tree_node, rb_entry, paging_rb_tree_node_cmp)
RB_GENERATE(paging_rb_tree, paging_rb_tree_node, rb_entry, paging_rb_tree_node_cmp)

static inline void rb_vnode_insert(struct paging_state *st, size_t level,
                                   struct paging_vnode_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_INSERT(paging_rb_tree, &st->vnode_tree[level], (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline void rb_vnode_remove(struct paging_state *st, size_t level,
                                   struct paging_vnode_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_REMOVE(paging_rb_tree, &st->vnode_tree[level], (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline void rb_region_insert(struct paging_state *st, struct paging_region_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_INSERT(paging_rb_tree, &st->region_tree, (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline void rb_region_remove(struct paging_state *st, struct paging_region_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_REMOVE(paging_rb_tree, &st->region_tree, (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline void rb_mapping_insert(struct paging_state *st,
                                     struct paging_mapping_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_INSERT(paging_rb_tree, &st->mapping_tree, (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline void rb_mapping_remove(struct paging_state *st,
                                     struct paging_mapping_node *n)
{
    CRITICAL_SECTION_ENTER
    {
        RB_REMOVE(paging_rb_tree, &st->mapping_tree, (struct paging_rb_tree_node *)n);
    }
    CRITICAL_SECTION_EXIT
}

static inline struct paging_vnode_node *rb_vnode_find(struct paging_state *st,
                                                      size_t level, lvaddr_t addr)
{
    struct paging_vnode_node find;
    find.addr = addr;
    return (struct paging_vnode_node *)RB_FIND(paging_rb_tree, &st->vnode_tree[level],
                                               (struct paging_rb_tree_node *)&find);
}

static inline struct paging_region_node *rb_region_find(struct paging_state *st,
                                                        lvaddr_t addr)
{
    struct paging_region_node find;
    find.addr = addr;
    return (struct paging_region_node *)RB_FIND(paging_rb_tree, &st->region_tree,
                                                (struct paging_rb_tree_node *)&find);
}

static inline struct paging_mapping_node *rb_mapping_find(struct paging_state *st,
                                                          lvaddr_t addr)
{
    struct paging_mapping_node find;
    find.addr = addr;
    return (struct paging_mapping_node *)RB_FIND(paging_rb_tree, &st->mapping_tree,
                                                 (struct paging_rb_tree_node *)&find);
}

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static inline errval_t pt_alloc(struct paging_state *st, enum objtype type,
                                struct capref *ret)
{
    errval_t err;
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        goto FAILURE_SLOT_ALLOC;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        goto FAILURE_VNODE_CREATE;
    }
    return SYS_ERR_OK;

FAILURE_VNODE_CREATE:
    st->slot_alloc->free(st->slot_alloc, *ret);
FAILURE_SLOT_ALLOC:
    return err;
}

static inline size_t get_child_index(lvaddr_t vaddr, size_t level)
{
    return FIELD((VMSAv8_64_L0_BITS - (VMSAv8_64_PTABLE_BITS * level)),
                 VMSAv8_64_PTABLE_BITS, vaddr);
}


static inline uint64_t flags_to_attr(int flags)
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

static inline void decode_indices(size_t level, lvaddr_t rvaddr, size_t bytes,
                                  size_t *ret_inclusive_start, size_t *ret_exclusive_end,
                                  size_t *ret_count)
{
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];

    size_t start_index = get_child_index(rvaddr, level);
    size_t end_index = get_child_index(ROUND_UP(rvaddr + bytes, CHILD_SIZE), level);
    if (end_index == 0) {  // wrap around
        end_index = 512;
    }

    assert(start_index < end_index);
    assert(end_index <= 512);
    assert((end_index - start_index) * CHILD_SIZE >= bytes);

    *ret_inclusive_start = start_index;
    *ret_exclusive_end = end_index;
    *ret_count = end_index - start_index;
}

/**
 * \brief Helper function to map src (frame or vnode) into dest (vnode)
 *        Will not trigger slot refill.
 */
static inline errval_t apply_mapping(struct paging_state *st, struct capref dest,
                                     struct capref src, capaddr_t slot, uint64_t attr,
                                     uint64_t off, uint64_t pte_count,
                                     struct paging_mapping_node_head *mappings,
                                     bool store_frame_cap)
{
    assert(!capref_is_null(dest));
    assert(!capref_is_null(src));
    errval_t err;

    // Allocate the mapping capability slot
    struct capref mapping_cap;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto FAILURE_SLOT_ALLOC;
    }

    // Apply the mapping
    err = vnode_map(dest, src, slot, attr, off, pte_count, mapping_cap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_VNODE_MAP);
        DEBUG_PRINTF("failed to vnode_map\n");
        goto FAILURE_VNODE_MAP;
    }

    if (mappings) {
        struct paging_mapping_child_node *child = slab_alloc(&st->mapping_child_slabs);
        memset(child, 0, sizeof(*child));  // NULL_CAP is 0
        child->vnode_cap = dest;
        child->mapping_cap = mapping_cap;
        if (store_frame_cap) {
            child->self_paging_frame_cap = src;
        }
        CRITICAL_SECTION_ENTER
        {
            LIST_INSERT_HEAD(mappings, child, link);
        }
        CRITICAL_SECTION_EXIT
    }  // discard otherwise

    return SYS_ERR_OK;

FAILURE_VNODE_MAP:
    st->slot_alloc->free(st->slot_alloc, mapping_cap);
FAILURE_SLOT_ALLOC:
    return err;
}

static inline struct paging_free_list_head *free_list_head(struct paging_state *st,
                                                           uint8_t bits)
{
    return &st->free_list[bits - BASE_PAGE_BITS];
}

static inline void insert_to_free_list(struct paging_state *st,
                                       struct paging_region_node *node)
{
    assert(!node->free);
    assert(node->bits >= BASE_PAGE_BITS && node->bits <= PAGING_ADDR_BITS);
    CRITICAL_SECTION_ENTER
    {
        LIST_INSERT_HEAD(free_list_head(st, node->bits), node, fl_link);
        node->free = true;
    }
    CRITICAL_SECTION_EXIT
}

static inline void remove_from_free_list(struct paging_state *st,
                                         struct paging_region_node *node)
{
    assert(node->free);
    CRITICAL_SECTION_ENTER
    {
        node->free = false;
        LIST_REMOVE(node, fl_link);
    }
    CRITICAL_SECTION_EXIT
}

// Create a node. cap is initialized to NULL_CAP. link is not initialized.
static inline errval_t create_vnode_node(struct paging_state *st, lvaddr_t addr,
                                         size_t level, struct paging_vnode_node **ret)
{
    assert(level < PAGING_TABLE_LEVELS);
    struct paging_vnode_node *n = slab_alloc(&st->vnode_slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    memset(n, 0, sizeof(*n));  // NULL_CAP is all 0
    n->addr = addr;
    if (ret) {
        *ret = n;
    }
    rb_vnode_insert(st, level, n);
    return SYS_ERR_OK;
}

static inline void delete_vnode_node(struct paging_state *st, size_t level,
                                     struct paging_vnode_node *n)
{
    assert(level < PAGING_TABLE_LEVELS);
    rb_vnode_remove(st, level, n);
    slab_free(&st->vnode_slabs, n);
}

static inline errval_t create_and_install_vnode_node(struct paging_state *st,
                                                     lvaddr_t addr, size_t level,
                                                     struct capref parent_cap,
                                                     struct paging_vnode_node **node_ptr)
{
    errval_t err;

    // Create the table node
    err = create_vnode_node(st, addr, level, node_ptr);
    if (err_is_fail(err)) {
        goto FAILURE_CREATE_VNODE_NODE;
    }

    // Create the page table
    err = pt_alloc(st, PAGE_TABLE_TYPE[level], &(*node_ptr)->vnode_cap);
    if (err_is_fail(err)) {
        goto FAILURE_PT_ALLOC;
    }

    // Install the page table
    err = apply_mapping(st, parent_cap, (*node_ptr)->vnode_cap,
                        get_child_index(addr, level - 1),
                        KPI_PAGING_FLAGS_READ | KPI_PAGING_FLAGS_WRITE, 0, 1, NULL, false);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to apply_mapping (create_and_install_vnode_node)\n");
        goto FAILURE_APPLY_MAPPING;
    }

    return SYS_ERR_OK;

FAILURE_APPLY_MAPPING:
    cap_destroy((*node_ptr)->vnode_cap);
FAILURE_PT_ALLOC:
    delete_vnode_node(st, level, *node_ptr);
FAILURE_CREATE_VNODE_NODE:
    return err;
}

static errval_t lookup_or_create_vnode_node(struct paging_state *st, size_t level,
                                            lvaddr_t addr, struct paging_vnode_node **ret)
{
    assert(level < PAGING_TABLE_LEVELS);
    assert((addr & TABLE_ADDR_MASK[level]) == 0);

#if 0
    DEBUG_PRINTF("lookup_or_create_vnode_node(%lu) 0x%lx\n", level, addr);
#endif

    errval_t err;

    struct paging_vnode_node *node = rb_vnode_find(st, level, addr);
    if (node != NULL) {
        goto DONE;
    }

    // Create vnode from the upper level vnode
    assert(level > 0 && "L0 node not exist");
    struct paging_vnode_node *parent = NULL;
    err = lookup_or_create_vnode_node(st, level - 1, addr & ~(TABLE_ADDR_MASK[level - 1]),
                                      &parent);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("lookup_or_create_vnode_node(%lu) failed\n", level);
        return err;  // return directly, no need to clean up
    }
    assert(!capref_is_null(parent->vnode_cap));

    // The operation above may trigger refill/vnode alloc that creates the vnode node
    node = rb_vnode_find(st, level, addr);
    if ((node = rb_vnode_find(st, level, addr)) != NULL) {
        goto DONE;
    }

    // Create the vnode cap
    struct capref vnode_cap;
    err = pt_alloc(st, PAGE_TABLE_TYPE[level], &vnode_cap);
    if (err_is_fail(err)) {
        goto FAILURE_PT_ALLOC;
    }

    // The operation above may trigger refill/vnode alloc that creates the vnode node
    if ((node = rb_vnode_find(st, level, addr)) != NULL) {
        err = SYS_ERR_OK;  // fall back to the undo path, but return OK
        goto UNDO_PT_ALLOC;
    }

    // Install the page table
    err = apply_mapping(st, parent->vnode_cap, vnode_cap, get_child_index(addr, level - 1),
                        KPI_PAGING_FLAGS_READ | KPI_PAGING_FLAGS_WRITE, 0, 1, NULL, false);
    if ((node = rb_vnode_find(st, level, addr)) != NULL) {
        err = SYS_ERR_OK;  // fall back to the undo path, and return OK, regardless of error
        goto UNDO_PT_ALLOC;
    }
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to apply_mapping (lookup_or_create_vnode_node)\n");
        goto FAILURE_APPLY_MAPPING;
    }

    // Create the vnode node, should not trigger refill
    err = create_vnode_node(st, addr, level, &node);
    if (err_is_fail(err)) {
        goto FAILURE_CREATE_VNODE_NODE;
    }
    node->vnode_cap = vnode_cap;

DONE:
    *ret = node;
    assert(!capref_is_null(node->vnode_cap));
    return SYS_ERR_OK;

FAILURE_CREATE_VNODE_NODE:
FAILURE_APPLY_MAPPING:
UNDO_PT_ALLOC:
    cap_destroy(vnode_cap);
FAILURE_PT_ALLOC:
    *ret = node;
    return err;
}

// free is initialized to false
static inline errval_t create_region_node(struct paging_state *st, lvaddr_t addr,
                                          uint8_t bits, struct paging_region_node **ret)
{
    struct paging_region_node *n = slab_alloc(&st->region_slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    memset(n, 0, sizeof(*n));  // NULL_CAP is all 0
    n->addr = addr;
    n->bits = bits;
    n->free = false;
    if (ret) {
        *ret = n;
    }
    rb_region_insert(st, n);
    return SYS_ERR_OK;
}

static inline errval_t lookup_or_create_region_node(struct paging_state *st,
                                                    lvaddr_t addr, uint8_t bits,
                                                    struct paging_region_node **ret,
                                                    bool create)
{
    errval_t err = SYS_ERR_OK;

    struct paging_region_node *node;
    THREAD_MUTEX_ENTER(&st->region_mutex)
    {
        node = rb_region_find(st, addr);
        if (node == NULL && create) {
            // Create the region node
            err = create_region_node(st, addr, bits, &node);
        }
    }
    THREAD_MUTEX_EXIT(&st->region_mutex)
    if (err_is_fail(err)) {
        return err;
    }

    if (node != NULL && node->bits != bits) {
        node = NULL;
    }

    if (node != NULL) {
        assert(node->addr == addr);
    }

    *ret = node;
    return node != NULL ? SYS_ERR_OK : LIB_ERR_PAGING_REGION_NODE_NOT_FOUND;
}

static inline errval_t create_mapping_node(struct paging_state *st,
                                           struct paging_region_node *region,
                                           struct paging_mapping_node **ret)
{
    struct paging_mapping_node *n = slab_alloc(&st->mapping_node_slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    memset(n, 0, sizeof(*n));  // NULL_CAP is all 0
    n->addr = region->addr;
    n->region = region;
    LIST_INIT(&n->mappings);
    if (ret) {
        *ret = n;
    }
    rb_mapping_insert(st, n);
#if 0
    DEBUG_PRINTF("paging: new mapping node: 0x%lx/%lu\n", region->addr, BIT(region->bits))
#endif
    return SYS_ERR_OK;
}

static inline errval_t
unmap_and_delete_mapping_child(struct paging_state *st,
                               struct paging_mapping_child_node *child)
{
    errval_t err = vnode_unmap(child->vnode_cap, child->mapping_cap);
    if (err_is_fail(err)) {
        return err;
    }
    err = cap_destroy(child->mapping_cap);
    if (err_is_fail(err)) {
        return err;
    }
    if (!capref_is_null(child->self_paging_frame_cap)) {
        err = cap_destroy(child->self_paging_frame_cap);
        if (err_is_fail(err)) {
            return err;
        }
    }
    slab_free(&st->mapping_child_slabs, child);
    return SYS_ERR_OK;
}

static inline errval_t unmap_mapping_link(struct paging_state *st,
                                          struct paging_mapping_node_head *head)
{
    struct paging_mapping_child_node *child, *tmp;
    LIST_FOREACH_SAFE(child, head, link, tmp)
    {
        errval_t err = unmap_and_delete_mapping_child(st, child);
        if (err_is_fail(err)) {
            return err;
        }
    }
    return SYS_ERR_OK;
}

static inline errval_t unmap_and_delete_mapping_node(struct paging_state *st,
                                                     struct paging_mapping_node *n)
{
    // Unmap and delete all children mapping cap
    errval_t err = unmap_mapping_link(st, &n->mappings);
    if (err_is_fail(err)) {
        return err;
    }
    rb_mapping_remove(st, n);
#if 0
    DEBUG_PRINTF("paging: delete mapping node: 0x%lx/%lu\n", n->region->addr, BIT(n->region->bits))
#endif
    slab_free(&st->mapping_node_slabs, n);
    return SYS_ERR_OK;
}

static inline errval_t ensure_enough_slabs(struct paging_state *st)
{
    if (st->refilling) {
        return SYS_ERR_OK;
    }

    if (slab_freecount(&st->vnode_slabs) < VNODE_SLAB_REFILL_THRESHOLD) {
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill vnode slabs\n");
#endif
        st->refilling = true;
        errval_t err = st->vnode_slabs.refill_func(&st->vnode_slabs);
        st->refilling = false;
        if (err_is_fail(err)) {
            return err;
        }
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill vnode slabs done\n");
#endif
    }
    if (slab_freecount(&st->region_slabs) < REGION_SLAB_REFILL_THRESHOLD) {
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill region slabs\n");
#endif
        st->refilling = true;
        errval_t err = st->region_slabs.refill_func(&st->region_slabs);
        st->refilling = false;
        if (err_is_fail(err)) {
            return err;
        }
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill region slabs done\n");
#endif
    }
    if (slab_freecount(&st->mapping_node_slabs) < MAPPING_NODE_SLAB_REFILL_THRESHOLD) {
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill mapping node slabs\n");
#endif
        st->refilling = true;
        errval_t err = st->mapping_node_slabs.refill_func(&st->mapping_node_slabs);
        st->refilling = false;
        if (err_is_fail(err)) {
            return err;
        }
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill mapping node slabs done\n");
#endif
    }
    if (slab_freecount(&st->mapping_child_slabs) < MAPPING_CHILD_SLAB_REFILL_THRESHOLD) {
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill mapping child slabs\n");
#endif
        st->refilling = true;
        errval_t err = st->mapping_child_slabs.refill_func(&st->mapping_child_slabs);
        st->refilling = false;
        if (err_is_fail(err)) {
            return err;
        }
#if defined(DEBUG_REFILL)
        DEBUG_PRINTF("paging: refill mapping child slabs done\n");
#endif
    }
    return SYS_ERR_OK;
}

/**
 * Chop down a region to naturally aligned regions. The returned region is offset from
 * the input region by rvaddr. The input region must not be free. If it's a placeholder,
 * all resulting regions are set as placeholders and not added to the free lists.
 * Otherwise, newly created regions (except the returned one) are added to the free list.
 * @param st
 * @param node_ptr
 * @param rvaddr
 * @param bits
 * @return
 * @note Here is nothing we can do on failure of this function. The created region nodes
 *       are already in the rb tree, and we won't lose them. Just let the user retry.
 */
static errval_t chop_down_region(struct paging_state *st,
                                 struct paging_region_node **node_ptr, lvaddr_t rvaddr,
                                 uint8_t bits)
{
    struct paging_region_node *node = *node_ptr;
    assert(!node->free);
    assert(node->bits >= bits);

    errval_t err;

    while (node->bits > bits) {
        // Downgrade to next level
        node->bits--;
        struct paging_region_node *left = node;

        // Lookup or create buddy node
        struct paging_region_node *right = NULL;
        err = lookup_or_create_region_node(st, left->addr ^ BIT(left->bits), left->bits,
                                           &right, true);
        if (err_is_fail(err)) {
            return err;  // here is nothing much we can do here
        }

        assert(left->addr + BIT(left->bits) == right->addr);
        assert(!left->free);
        assert(!right->free);

        if (rvaddr < BIT(left->bits)) {
            insert_to_free_list(st, right);
            node = left;
        } else {
            insert_to_free_list(st, left);
            node = right;
            rvaddr -= BIT(left->bits);
        }
    }
    *node_ptr = node;
    return SYS_ERR_OK;
}

/**
 * Map a frame that can cross multiple page tables.
 * @param st
 * @param addr
 * @param frame
 * @param offset
 * @param bytes
 * @param attr            If 0, immediately return SYS_ERR_OK.
 * @param mappings
 * @param store_frame_cap If true, store the frame capability to ONE OF the
 *                        paging_mapping_child_node that is created (no guarantee on which
 *                        one)
 * @return
 * @note  On error, this function guaranteed that all mappings that are already performed
 *        are inserted into the HEAD of mappings. Page table construction is not reversed.
 */
static errval_t map_frame(struct paging_state *st, lvaddr_t addr, struct capref frame,
                          size_t offset, size_t bytes, uint64_t attr,
                          struct paging_mapping_node_head *mappings, bool store_frame_cap)
{
    if (attr == 0) {  // for placeholder
        return SYS_ERR_OK;
    }

#if 0
    DEBUG_PRINTF("map_frame 0x%lx/%lu, offset = 0x%lu\n", addr, bytes, offset);
#endif

    //    assert(ROUND_UP(bytes, BASE_PAGE_SIZE) == bytes);
    assert(ROUND_UP(offset, BASE_PAGE_SIZE) == offset);

    errval_t err;

    lvaddr_t l3_addr_start = ROUND_DOWN(addr, VMSAv8_64_L2_BLOCK_SIZE);
    lvaddr_t l3_addr_end = ROUND_UP(addr + bytes, VMSAv8_64_L2_BLOCK_SIZE);

    for (lvaddr_t l3_addr = l3_addr_start; l3_addr < l3_addr_end;
         l3_addr += VMSAv8_64_L2_BLOCK_SIZE) {
        err = ensure_enough_slabs(st);
        if (err_is_fail(err)) {
            return err;
        }

        lvaddr_t child_start_vaddr = max(l3_addr, addr);
        lvaddr_t child_end_vaddr = min(l3_addr + VMSAv8_64_L2_BLOCK_SIZE, addr + bytes);
        size_t child_mapping_size = child_end_vaddr - child_start_vaddr;

        // Get the L3 page table node
        struct paging_vnode_node *l3_node = NULL;
        THREAD_MUTEX_ENTER(&st->vnode_mutex)
        {
            err = lookup_or_create_vnode_node(st, 3, l3_addr, &l3_node);
        }
        THREAD_MUTEX_EXIT(&st->vnode_mutex)
        if (err_is_fail(err)) {
            return err;
        }
        assert(l3_node != NULL);

        // Apply mapping all at once
        size_t child_start, child_end, child_count;
        decode_indices(3, child_start_vaddr - l3_addr, child_mapping_size, &child_start,
                       &child_end, &child_count);
#if 0
        debug_printf("child_start = %lu, end = %lu, count = %lu; offset = %lu\n", child_start, child_end, child_count, offset);
#endif

        // Allocate the mapping capability slot
        struct capref mapping_cap;
        err = st->slot_alloc->alloc(st->slot_alloc, &mapping_cap);
        if (err_is_fail(err)) {
            return err;
        }

        assert(!capref_is_null(l3_node->vnode_cap));
        err = apply_mapping(st, l3_node->vnode_cap, frame, child_start, attr, offset,
                            child_count, mappings, store_frame_cap);
        store_frame_cap = false;  // no longer store the frame
        if (err_is_fail(err)) {
            DEBUG_PRINTF("failed to apply_mapping (map_frame, child_count = %lu)\n",
                         child_count);
            st->slot_alloc->free(st->slot_alloc, mapping_cap);
            return err;
        }
        offset += child_mapping_size;
    }

    return SYS_ERR_OK;
}

/**
 * Map to a naturally aligned region. The region must be either free or a placeholder.
 * @param st
 * @param vaddr
 * @param bits
 * @param frame
 * @param bytes   Size of the frame to be mapped. Doesn't need to be power of two.
 * @param offset
 * @param attr    If 0, frame and offset is ignored and no actual mapping is performed.
 *                Can be used to create invalid regions.
 *
 * @return
 * @note  On error, mapping is undone in this function.
 */
static errval_t map_naturally_aligned_fixed(struct paging_state *st, lvaddr_t vaddr,
                                            uint8_t bits, struct capref frame,
                                            size_t bytes, size_t offset, uint64_t attr)
{
#if 0
    DEBUG_PRINTF("map_naturally_aligned_fixed 0x%lx/%lu, offset = 0x%lu\n", vaddr,
                 BIT(bits), offset);
#endif

    assert(bits >= BASE_PAGE_BITS);
    assert((vaddr & MASK(bits)) == 0 && "not naturally aligned");

    errval_t err, err2;

    err = ensure_enough_slabs(st);
    if (err_is_fail(err)) {
        return err;  // here is nothing much we can do here
    }

    struct paging_region_node *node = NULL;
    struct paging_mapping_node *mapping = NULL;

    THREAD_MUTEX_ENTER(&st->free_list_mutex)
    {
        // Find a free block as small as possible
        for (uint8_t b = bits; b <= PAGING_ADDR_BITS; b++) {
            err = lookup_or_create_region_node(st, vaddr & ~MASK(b), b, &node, false);
            if (err_is_ok(err)) {
                if (node->free) {
                    remove_from_free_list(st, node);
                } else {
                    continue;  // look for a larger one
                }

                err = chop_down_region(st, &node, vaddr - node->addr, bits);
                if (err_is_fail(err)) {
                    DEBUG_PRINTF("Failed to chop_down_region\n");
                    goto EXIT_FIND_BLOCK;
                }
                assert(node->bits == bits && node->addr == vaddr);

                goto EXIT_FIND_BLOCK;

            } else if (err == LIB_ERR_PAGING_REGION_NODE_NOT_FOUND) {
                // Continue to next order
            } else {
                // Other error, no need to clean up
                return err;
            }
        }
    EXIT_FIND_BLOCK:
        THREAD_MUTEX_BREAK;
    }
    THREAD_MUTEX_EXIT(&st->free_list_mutex)
    if (err_is_fail(err)) {
        goto FAILURE_CHOP_DOWN_REGION;
    }

    if (node != NULL) {
        // Create the mapping record
        err = create_mapping_node(st, node, &mapping);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("Failed to create_mapping_node\n");
            goto FAILURE_CREATE_MAPPING_NODE;
        }

        // Actually map the frame, which may span multiple tables
        err = map_frame(st, vaddr, frame, offset, bytes, attr, &mapping->mappings, false);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("failed to map_frame (map_naturally_aligned_fixed)\n");
            goto FAILURE_MAP_FRAME;
        }

        assert(!node->free);

        return SYS_ERR_OK;
    } else {
        // DEBUG_PRINTF("paging: fixed mapping to already used region\n");
        return LIB_ERR_PAGING_FIXED_MAP_OCCUPIED;
    }

FAILURE_MAP_FRAME:
    // Continue to unmap_and_delete

    err2 = unmap_and_delete_mapping_node(st, mapping);
    if (err_is_fail(err2)) {
        DEBUG_PRINTF("unmap_and_delete_mapping_node failed on the way handling "
                     "failure\n");
        err = err_push(err, err2);
    }
FAILURE_CREATE_MAPPING_NODE:
    // Nothing to do on failure of chop_down_region, see its comment
FAILURE_CHOP_DOWN_REGION:
    return err;
}

static errval_t map_fixed(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                          size_t offset, size_t bytes, uint64_t attr)
{
#if 0
    DEBUG_PRINTF("map_fixed 0x%lx/%lu, offset = 0x%lu\n", vaddr, bytes, offset);
#endif

    assert(bytes > 0 && bytes == ROUND_UP(bytes, BASE_PAGE_SIZE));

    errval_t err;

    for (uint8_t bits = log2floor(bytes); bits >= BASE_PAGE_BITS; bits--) {
        const lvaddr_t BLOCK_SIZE = BIT(bits);
        lvaddr_t start = ROUND_UP(vaddr, BLOCK_SIZE);  // naturally aligned
        lvaddr_t end = start + BLOCK_SIZE;
        if (end <= vaddr + bytes) {
            // Map the region
            assert(BIT(bits) <= bytes);
            err = map_naturally_aligned_fixed(st, start, bits, frame, BIT(bits),
                                              offset + start - vaddr, attr);
            if (err_is_fail(err)) {
                return err;  // on error, mapping is undone in this function
            }
            if (vaddr < start) {
                // Map the heading region
                err = map_fixed(st, vaddr, frame, offset, start - vaddr, attr);
                if (err_is_fail(err)) {
                    return err;
                }
            }
            if (vaddr + bytes > end) {
                // Map the tailing region
                err = map_fixed(st, end, frame, offset + end - vaddr, vaddr + bytes - end,
                                attr);
                if (err_is_fail(err)) {
                    return err;
                }
            }
            return SYS_ERR_OK;
        }
    }
    assert(!"should never reach here");
}

/**
 * Map a frame on a node.
 * @param st
 * @param buf
 * @param bits
 * @param node
 * @param frame
 * @param bytes   Actual size of the frame. Doesn't need to be power of two.
 * @param attr
 * @return
 * @note  On error, mapping is undone in this function.
 */
static errval_t map_dynamic_using_node(struct paging_state *st, void **buf, uint8_t bits,
                                       struct paging_region_node *node,
                                       struct capref frame, size_t bytes, uint64_t attr)
{
#if 0
    DEBUG_PRINTF("map_dynamic_using_node node=0x%lx << %u, frame bytes = %lu\n",
                 node->addr, node->bits, bytes);
#endif
    errval_t err, err2;

    struct paging_mapping_node *mapping = NULL;

    err = create_mapping_node(st, node, &mapping);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to create_mapping_node\n");
        goto FAILURE_CREATE_MAPPING_NODE;
    }

    // Actually map the frame, which may span multiple tables
    err = map_frame(st, node->addr, frame, 0, bytes, attr, &mapping->mappings, false);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to map_frame (map_dynamic_using_node node=0x%lx << %u, "
                     "frame bytes = %lu)\n",
                     node->addr, node->bits, bytes);
        goto FAILURE_MAP_FRAME;
    }


    *buf = (void *)node->addr;
    assert(!node->free);

#if 0
    DEBUG_PRINTF("map_dynamic_using_node gives out 0x%lx/%lu\n", node->addr, bytes);
#endif

    return SYS_ERR_OK;

FAILURE_MAP_FRAME:
    // Continue to unmap_and_delete

    err2 = unmap_and_delete_mapping_node(st, mapping);
    if (err_is_fail(err2)) {
        DEBUG_PRINTF("unmap_and_delete_mapping_node failed on the way handling "
                     "failure\n");
        err = err_push(err, err2);
    }
FAILURE_CREATE_MAPPING_NODE:
    return err;
}

static errval_t map_dynamic(struct paging_state *st, void **buf, size_t bytes,
                            size_t alignment, struct capref frame, uint64_t attr)
{
    errval_t err = SYS_ERR_OK;

    err = ensure_enough_slabs(st);
    if (err_is_fail(err)) {
        return err;  // here is nothing much we can do here
    }

#if 0
    DEBUG_PRINTF("map_dynamic bytes=%lu, alignment = 0x%lu\n", bytes, alignment);
#endif

    uint8_t bits = max(BASE_PAGE_BITS, log2ceil(bytes));
    uint8_t align_bits = max(BASE_PAGE_BITS, log2ceil(alignment));

    struct paging_region_node *node = NULL;

    // Fast path: start from align_bits
    THREAD_MUTEX_ENTER(&st->free_list_mutex)
    {
        for (uint8_t b = max(bits, align_bits); b <= PAGING_ADDR_BITS; b++) {
            if (!LIST_EMPTY(free_list_head(st, b))) {
                node = LIST_FIRST(free_list_head(st, b));
                remove_from_free_list(st, node);

                err = chop_down_region(st, &node, 0, bits);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "failed to chop_down_region\n");
                    while (1)
                        ;
                    goto EXIT_FAST_PATH;
                }
                assert(node->bits == bits);

                goto EXIT_FAST_PATH;
            }
        }
    EXIT_FAST_PATH:
        THREAD_MUTEX_BREAK;
    }
    THREAD_MUTEX_EXIT(&st->free_list_mutex)
    if (err_is_fail(err)) {
        return err;  // Nothing to do on failure of chop_down_region, see its comment
    }

    if (node == NULL && bits < align_bits) {
        // Slow path: try every available region
        lvaddr_t align_mask = MASK(align_bits);

        THREAD_MUTEX_ENTER(&st->free_list_mutex)
        {
            for (uint8_t b = bits; b < align_bits; b++) {
                LIST_FOREACH(node, free_list_head(st, b), fl_link)
                {
                    if ((node->addr & align_mask) == 0) {
                        remove_from_free_list(st, node);

                        err = chop_down_region(st, &node, 0, bits);
                        if (err_is_fail(err)) {
                            DEBUG_ERR(err, "failed to chop_down_region\n");
                            goto EXIT_SLOW_PATH;
                        }
                        assert(node->bits == bits);

                        goto EXIT_SLOW_PATH;
                    }
                }
            }
        EXIT_SLOW_PATH:
            THREAD_MUTEX_BREAK;
        }
        THREAD_MUTEX_EXIT(&st->free_list_mutex)
        if (err_is_fail(err)) {
            return err;  // Nothing to do on failure of chop_down_region, see its comment
        }
    }

    if (node != NULL) {
        return map_dynamic_using_node(st, buf, bits, node, frame, bytes, attr);
    } else {
        // No available region
        return LIB_ERR_PAGING_NO_MEMORY;
    }
}

/**
 * Map a frame into a placeholder region.
 * @param st
 * @param vaddr
 * @param frame
 * @param bytes
 * @param offset
 * @param attr
 * @param store_frame_cap
 * @return
 * @note  On error, mapping is undone in this function.
 */
static errval_t map_into_placeholder(struct paging_state *st, lvaddr_t vaddr,
                                     struct capref frame, size_t bytes, size_t offset,
                                     uint64_t attr, bool store_frame_cap)
{
#if 0
    DEBUG_PRINTF("map_into_placeholder 0x%lx/%lu, offset = 0x%lu\n", vaddr, bytes, offset);
#endif

    assert(bytes > 0 && bytes == ROUND_UP(bytes, BASE_PAGE_SIZE));

    errval_t err, err2;

    struct paging_mapping_node *mapping = NULL;

    // Temporary storage for undo on failure
    struct paging_mapping_child_node *old_mapping_head;

    // Find the mapping by gradually marking out the address
    for (uint8_t b = log2ceil(bytes); b <= PAGING_ADDR_BITS; b++) {
        mapping = rb_mapping_find(st, vaddr & ~MASK(b));

#if 0
        if (mapping == NULL) {
            DEBUG_PRINTF("b = %u, mapping = NULL\n", b);
        } else {
            DEBUG_PRINTF("b = %u, mapping = 0x%lx/%u bits\n", b, mapping->addr,
                         mapping->region->bits);
        }
#endif

        if (mapping != NULL && mapping->region->bits == b
            && mapping->addr + BIT(mapping->region->bits) >= vaddr + bytes) {
            // Record the old mapping head for undo the operation
            old_mapping_head = LIST_FIRST(&mapping->mappings);

            // Actually map the frame, which may span multiple tables
            // map_frame ensures that new mapping are inserted to the head
            err = map_frame(st, vaddr, frame, offset, bytes, attr, &mapping->mappings,
                            store_frame_cap);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("failed to map_frame (map_into_placeholder)\n");
                goto FAILURE_MAP_FRAME;
            }

            return SYS_ERR_OK;

        } else {
            // Continue to next order
        }
    }
    return LIB_ERR_PAGING_PLACEHOLDER_NOT_FOUND;

FAILURE_MAP_FRAME:
    // Undo the mapping only in this function
    {
        struct paging_mapping_child_node *child, *tmp;
        LIST_FOREACH_SAFE(child, &mapping->mappings, link, tmp)
        {
            if (child == old_mapping_head) {
                break;
            }
            err2 = unmap_and_delete_mapping_child(st, child);
            if (err_is_fail(err2)) {
                err = err_push(err2, err2);
                break;
            }
        }
        mapping->mappings.lh_first = old_mapping_head;
    }

    return err;
}

/**
 * Unmap a region of memory.
 * @param st
 * @param vaddr
 * @param frame
 * @param bytes
 * @param offset
 * @param attr
 * @return
 * @note  On error, done unmapping is NOT reverted (mapped again).
 */
static errval_t unmap(struct paging_state *st, lvaddr_t vaddr)
{
#if 0
    DEBUG_PRINTF("unmap 0x%lx\n", vaddr);
#endif

    errval_t err;

    struct paging_mapping_node *mapping = rb_mapping_find(st, vaddr);
    if (mapping == NULL) {
        return LIB_ERR_PAGING_UNMAP_NOT_FOUND;
    }

    struct paging_region_node *node = mapping->region;
    assert(node->addr == mapping->addr);
    assert(!node->free);

    // Destroy the mapping caps
    unmap_and_delete_mapping_node(st, mapping);
    mapping = NULL;

    // Merge node iteratively
    THREAD_MUTEX_ENTER(&st->free_list_mutex)
    {
        while (node->bits < PAGING_ADDR_BITS) {
            // Lookup buddy node
            struct paging_region_node *buddy = NULL;
            const lvaddr_t buddy_addr = node->addr ^ BIT(node->bits);
            err = lookup_or_create_region_node(st, buddy_addr, node->bits, &buddy, false);
            if (err_is_fail(err) && err != LIB_ERR_PAGING_REGION_NODE_NOT_FOUND) {
                DEBUG_PRINTF("fail to lookup_or_create_region_node 0x%lx/%u bits\n",
                             buddy_addr, node->bits);
                goto EXIT_MERGE_BLOCK;
            }

            if (err == LIB_ERR_PAGING_REGION_NODE_NOT_FOUND || !buddy->free) {
                err = SYS_ERR_OK;
                break;  // the buddy is not free, or the buddy node is not at the same level
            } else {
                remove_from_free_list(st, buddy);
            }

            // Combine the node with its buddy and switch to the upper level one
            assert(node->bits == buddy->bits);
            if ((buddy->addr & BIT(buddy->bits)) == 0) {
                node = buddy;
            }
            node->bits++;
        }

        insert_to_free_list(st, node);

    EXIT_MERGE_BLOCK:
        THREAD_MUTEX_BREAK;
    }
    THREAD_MUTEX_EXIT(&st->free_list_mutex)
    if (err_is_fail(err)) {
        return err;
    }

#if 0
    DEBUG_PRINTF("unmap insert 0x%lx/%lu to free list\n", node->addr, BIT(node->bits));
#endif
    return SYS_ERR_OK;
}

static inline errval_t assert_arguments(struct paging_state *st, lvaddr_t vaddr,
                                        size_t *size)
{
    if (st == NULL) {
        // DEBUG_PRINTF("paging: NULL paging_state\n");
        return ERR_INVALID_ARGS;
    }
    if (vaddr < st->start_addr) {
        // DEBUG_PRINTF("paging: vaddr < start_addr\n");
        return ERR_INVALID_ARGS;
    }
    if (vaddr > BIT(PAGING_ADDR_BITS)) {
        // DEBUG_PRINTF("paging: vaddr too large\n");
        return ERR_INVALID_ARGS;
    }
    if (*size == 0) {
        // DEBUG_PRINTF("paging: cannot map size 0\n");
        return ERR_INVALID_ARGS;
    }
    if (*size >= BIT(PAGING_ADDR_BITS)) {
        // DEBUG_PRINTF("paging: size too large\n");
        return ERR_INVALID_ARGS;
    }
    //    *size = ROUND_UP(*size, BASE_PAGE_SIZE);
    return SYS_ERR_OK;
}

/**
 * DONE (M2): Implement this function.
 * DONE (M4): Improve this function.
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
    // DONE (M2): Implement state struct initialization
    // DONE (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.

    assert(ca != NULL);

    thread_mutex_init(&st->frame_alloc_mutex);
    thread_mutex_init(&st->free_list_mutex);
    thread_mutex_init(&st->vnode_mutex);
    thread_mutex_init(&st->region_mutex);
    st->slot_alloc = ca;
    st->start_addr = start_vaddr;

    slab_init(&st->region_slabs, sizeof(struct paging_region_node), slab_default_refill);
    slab_init(&st->vnode_slabs, sizeof(struct paging_vnode_node), slab_default_refill);
    slab_init(&st->mapping_node_slabs, sizeof(struct paging_mapping_node),
              slab_default_refill);
    slab_init(&st->mapping_child_slabs, sizeof(struct paging_mapping_child_node),
              slab_default_refill);

    if (!slab_buf_used) {
        // Paging is not setup yet so refill is not available
        slab_grow(&st->region_slabs, slab_buf[0], SLAB_INIT_BUF_SIZE);
        slab_grow(&st->vnode_slabs, slab_buf[1], SLAB_INIT_BUF_SIZE);
        slab_grow(&st->mapping_node_slabs, slab_buf[2], SLAB_INIT_BUF_SIZE);
        slab_grow(&st->mapping_child_slabs, slab_buf[3], SLAB_INIT_BUF_SIZE);
        slab_buf_used = true;
    }

    for (int i = 0; i < PAGING_TABLE_LEVELS; i++) {
        RB_INIT(&st->vnode_tree[i]);
    }
    RB_INIT(&st->region_tree);
    RB_INIT(&st->mapping_tree);

    for (int i = 0; i < PAGING_ADDR_BITS - BASE_PAGE_BITS + 1; i++) {
        LIST_INIT(&st->free_list[i]);
    }

    st->refilling = false;

    errval_t err;
    struct paging_vnode_node *l0 = NULL;
    THREAD_MUTEX_ENTER(&st->vnode_mutex)
    {
        err = create_vnode_node(st, 0, 0, &l0);
    }
    THREAD_MUTEX_EXIT(&st->vnode_mutex)
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to create L0 vnode node\n");
        return err;
    }
    l0->vnode_cap = pdir;

    struct paging_region_node *init_region = NULL;
    THREAD_MUTEX_ENTER(&st->region_mutex)
    {
        err = create_region_node(st, 0, PAGING_ADDR_BITS, &init_region);
    }
    THREAD_MUTEX_EXIT(&st->region_mutex)
    if (err_is_fail(err)) {
        DEBUG_PRINTF("failed to create L0 region node\n");
        return err;
    }
    insert_to_free_list(st, init_region);

    if (start_vaddr > 0) {
        // Grab the region before start_vaddr with attr 0, not actually mapping anything
        err = map_fixed(st, 0, NULL_CAP, 0, start_vaddr, 0);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("failed to grab the region before start_vaddr\n");
            return err;
        }
    }

    return SYS_ERR_OK;
}

/**
 * DONE(M2): Implement this function.
 * DONE (M4): Improve this function.
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
    // DONE (M2): Implement state struct initialization
    // DONE (M4): Implement page fault handler that installs frames when a page fault
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
    //    debug_printf("paging_init\n");
    // DONE (M2): Call paging_init_state for &current
    // DONE (M4): initialize self-paging handler
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

    err = set_page_fault_handler();
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
    errval_t err;

    struct capref frame = NULL_CAP;


    THREAD_MUTEX_ENTER(&get_current_paging_state()->frame_alloc_mutex)
    {
        err = frame_alloc(&frame, EXCEPTION_STACK_SIZE, NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_init_onthread: frame_alloc failed\n");
            err = err_push(err, LIB_ERR_FRAME_ALLOC);
            break;
        }
    }
    THREAD_MUTEX_EXIT(&get_current_paging_state()->frame_alloc_mutex)
    if (err_is_fail(err)) {
        return err;
    }

    err = paging_map_frame(get_current_paging_state(), &t->exception_stack,
                           EXCEPTION_STACK_SIZE, frame);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_init_onthread: paging_map_frame failed\n");
        return err_push(err, LIB_ERR_PAGING_MAP);
    }


    t->exception_stack_top = t->exception_stack + EXCEPTION_STACK_SIZE;

    t->exception_handler = page_fault_handler;

    return SYS_ERR_OK;
}

/**
 * @brief Find a free region of virtual address space that is large enough to
 * accomodate a buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went
 * wrong otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    errval_t err = assert_arguments(st, st->start_addr /* useless */, &bytes);
    if (err_is_fail(err)) {
        return err;
    }

    return map_dynamic(st, buf, bytes, alignment, NULL_CAP, 0);
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
    errval_t err = assert_arguments(st, st->start_addr /* useless */, &bytes);
    if (err_is_fail(err)) {
        return err;
    }

    return map_dynamic(st, buf, bytes, BASE_PAGE_SIZE, frame, flags_to_attr(flags));
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
    errval_t err;

    err = assert_arguments(st, vaddr, &bytes);
    if (err_is_fail(err)) {
        return err;
    }

    // Try placeholder
    err = map_into_placeholder(st, vaddr, frame, bytes, 0, flags_to_attr(flags), false);
    if (err_is_ok(err)) {
        return SYS_ERR_OK;
    } else if (err != LIB_ERR_PAGING_PLACEHOLDER_NOT_FOUND) {
        return err;  // unhandled region
    }

    // Try mapping new
    return map_fixed(st, vaddr, frame, 0, bytes, flags_to_attr(flags));
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
    return unmap(st, (lvaddr_t)region);
}

static void __attribute((noreturn))
handle_real_page_fault(enum exception_type type, int subtype, void *addr,
                       arch_registers_state_t *regs)
{
    DEBUG_PRINTF("unhandled page fault (subtype %d) on %" PRIxPTR " at IP %" PRIxPTR "\n",
                 subtype, (size_t)addr, regs->named.pc);

    // dump hw page tables
    // debug_dump_hw_ptables();

    // print out stuff
    // debug_print_save_area(regs);
    // debug_dump(regs);
    debug_call_chain(regs);

    exit(EXIT_FAILURE);
}

static void page_fault_handler(enum exception_type type, int subtype, void *addr,
                               arch_registers_state_t *regs)
{
    if (type == EXCEPT_PAGEFAULT) {
#if 0
        DEBUG_PRINTF("paging: going to handle page fault at %p...\n", addr);
#endif

        if (addr == NULL) {
            handle_real_page_fault(type, subtype, addr, regs);
        }

        errval_t err;
        struct capref frame = NULL_CAP;

        THREAD_MUTEX_ENTER(&get_current_paging_state()->frame_alloc_mutex)
        {
            err = frame_alloc(&frame, BASE_PAGE_SIZE, NULL);
            if (err_is_fail(err)) {
                USER_PANIC_ERR(err, "paging_page_fault_handler: frame_alloc failed\n");
            }
        }
        THREAD_MUTEX_EXIT(&get_current_paging_state()->frame_alloc_mutex)

        err = map_into_placeholder(
            get_current_paging_state(), ROUND_DOWN((lvaddr_t)addr, BASE_PAGE_SIZE), frame,
            BASE_PAGE_SIZE, 0, flags_to_attr(VREGION_FLAGS_READ_WRITE), true);
        if (err_is_fail(err)) {
            // XXX: the frame capability may or may not be stored yet, ignore it for now
            handle_real_page_fault(type, subtype, addr, regs);
        } else {
#if 1
            DEBUG_PRINTF("paging: installed page to %p\n", addr);
#endif
        }

    } else {
        DEBUG_PRINTF("Fault! type = %d, subtype = %d, addr = %p\n", type, subtype, addr);
        exit(EXIT_FAILURE);
    }
}
__attribute__((__unused__)) static errval_t set_page_fault_handler(void)
{
    errval_t err;
    err = thread_set_exception_handler(page_fault_handler, NULL, exception_stack,
                                       exception_stack + EXCEPTION_STACK_SIZE, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging: fail to set exception handler");
        return err;
    } else {
        DEBUG_PRINTF("page fault handler set\n");
    }
    return SYS_ERR_OK;
}