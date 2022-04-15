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

#define SLAB_INIT_BUF_SIZE 8192
static char slab_buf[2][SLAB_INIT_BUF_SIZE];
static bool slab_buf_used = false;

#define REGION_SLAB_REFILL_THRESHOLD (PAGING_ADDR_BITS - BASE_PAGE_BITS)
#define VNODE_SLAB_REFILL_THRESHOLD 8

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

/// RB tree implementations for general nodes and wrapper functions

int paging_rb_tree_node_cmp(struct paging_rb_tree_node *e1, struct paging_rb_tree_node *e2)
{
    return (e1->addr < e2->addr ? -1 : e1->addr > e2->addr);
}

RB_PROTOTYPE(paging_rb_tree, paging_rb_tree_node, rb_entry, paging_rb_tree_node_cmp)
RB_GENERATE(paging_rb_tree, paging_rb_tree_node, rb_entry, paging_rb_tree_node_cmp)

static inline void rb_vnode_insert(struct paging_state *st, size_t level,
                                   struct paging_vnode_node *n)
{
    RB_INSERT(paging_rb_tree, &st->vnode_tree[level], (struct paging_rb_tree_node *)n);
}

static inline void rb_region_insert(struct paging_state *st, struct paging_region_node *n)
{
    RB_INSERT(paging_rb_tree, &st->region_tree, (struct paging_rb_tree_node *)n);
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
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
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

// For mapping either frame or vnode in vnode
// Can trigger slot refill
static inline errval_t apply_mapping(struct paging_state *st, struct capref dest,
                                     struct capref src, capaddr_t slot, uint64_t attr,
                                     uint64_t off, uint64_t pte_count,
                                     struct capref *ret_mapping_cap)
{
    assert(!capref_is_null(dest));
    assert(!capref_is_null(src));
    errval_t err;

    // Allocate the mapping capability slot
    struct capref mapping_cap;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    // Apply the mapping
    err = vnode_map(dest, src, slot, attr, off, pte_count, mapping_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VNODE_MAP);
    }

    if (ret_mapping_cap) {
        *ret_mapping_cap = mapping_cap;
    }  // discard otherwise

    return SYS_ERR_OK;
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
    assert(!node->placeholder);
    assert(node->bits >= BASE_PAGE_BITS && node->bits <= PAGING_ADDR_BITS);
    LIST_INSERT_HEAD(free_list_head(st, node->bits), node, fl_link);
    node->free = true;
}

static inline void remove_from_free_list(struct paging_region_node *node)
{
    assert(node->free);
    assert(!node->placeholder);
    node->free = false;
    LIST_REMOVE(node, fl_link);
}

// Create a node. cap is initialized to NULL_CAP. link is not initialized
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

static inline errval_t create_and_install_vnode_node(struct paging_state *st,
                                                     lvaddr_t addr, size_t level,
                                                     size_t index,
                                                     struct capref parent_cap,
                                                     struct paging_vnode_node **node_ptr)
{
    if (*node_ptr == NULL) {
        errval_t err;

        // Create the table node
        err = create_vnode_node(st, addr, level, node_ptr);
        if (err_is_fail(err)) {
            return err;
        }

        // Create the page table
        err = pt_alloc(st, PAGE_TABLE_TYPE[level], &(*node_ptr)->vnode_cap);
        if (err_is_fail(err)) {
            return err;
        }

        // Install the page table
        err = apply_mapping(st, parent_cap, (*node_ptr)->vnode_cap, index,
                            KPI_PAGING_FLAGS_READ | KPI_PAGING_FLAGS_WRITE, 0, 1, NULL);
        if (err_is_fail(err)) {
            return err;
        }
    }
    return SYS_ERR_OK;
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

    if (node == NULL) {
        // Create vnode from the upper level vnode
        assert(level > 0 && "L0 node not exist");
        struct paging_vnode_node *parent = NULL;
        err = lookup_or_create_vnode_node(st, level - 1,
                                          addr & ~(TABLE_ADDR_MASK[level - 1]), &parent);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("lookup_or_create_vnode_node(%lu) failed\n", level);
            return err;
        }

        // Create and install the current vnode
        assert(!capref_is_null(parent->vnode_cap));
        err = create_and_install_vnode_node(
            st, addr, level, get_child_index(addr, level - 1), parent->vnode_cap, &node);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "create_and_install_vnode_node(%lu) index=%lu failed\n", level,
                      get_child_index(addr, level - 1));
            return err;
        }
    }

    *ret = node;
    return SYS_ERR_OK;
}

// free and placeholder initialized to false
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
    n->placeholder = false;
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
    errval_t err;

    struct paging_region_node *node = rb_region_find(st, addr);

    if (node == NULL && create) {
        // Create the region node
        err = create_region_node(st, addr, bits, &node);
        if (err_is_fail(err)) {
            return err;
        }
    }

    if (node != NULL && node->bits != bits) {
        node = NULL;
    }

    if (node != NULL) {
        assert(node->addr == addr);
    }

    *ret = node;
    return node != NULL ? SYS_ERR_OK : MM_ERR_FIND_NODE;
}

static inline errval_t ensure_enough_slabs(struct paging_state *st)
{
    if (!st->refilling && slab_freecount(&st->vnode_slabs) < VNODE_SLAB_REFILL_THRESHOLD) {
        // DEBUG_PRINTF("paging: refill slabs\n");
        st->refilling = true;
        errval_t err = st->vnode_slabs.refill_func(&st->vnode_slabs);
        if (err_is_fail(err)) {
            return err;
        }
        st->refilling = false;
        // DEBUG_PRINTF("paging: refill slabs done\n");
    }
    if (!st->refilling
        && slab_freecount(&st->region_slabs) < REGION_SLAB_REFILL_THRESHOLD) {
        // DEBUG_PRINTF("paging: refill slabs\n");
        st->refilling = true;
        errval_t err = st->region_slabs.refill_func(&st->region_slabs);
        if (err_is_fail(err)) {
            return err;
        }
        st->refilling = false;
        // DEBUG_PRINTF("paging: refill slabs done\n");
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
        err = ensure_enough_slabs(st);
        if (err_is_fail(err)) {
            return err;
        }

        // Downgrade to next level
        node->bits--;
        struct paging_region_node *left = node;

        // Lookup or create buddy node
        struct paging_region_node *right = NULL;
        err = lookup_or_create_region_node(st, left->addr | BIT(left->bits), left->bits,
                                           &right, true);
        if (err_is_fail(err)) {
            return err;
        }

        // XXX: may need to think about this once unmapping is supported
        assert(!right->placeholder);
        right->placeholder = left->placeholder;
        assert(left->addr + BIT(left->bits) == right->addr);
        assert(!left->free);
        assert(!right->free);

        if (rvaddr < BIT(left->bits)) {
            if (!right->placeholder) {
                insert_to_free_list(st, right);
            }
            node = left;
        } else {
            if (!left->placeholder) {
                insert_to_free_list(st, left);
            }
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
 * @param ret_mapping_cap
 * @return
 */
static errval_t map_frame(struct paging_state *st, lvaddr_t addr, struct capref frame,
                          size_t offset, size_t bytes, uint64_t attr,
                          struct capref *ret_mapping_cap)
{
    if (attr == 0) {
        return SYS_ERR_OK;
    }

#if 0
    DEBUG_PRINTF("map_frame 0x%lx/%lu, offset = 0x%lu\n", addr, bytes, offset);
#endif

    assert(ROUND_UP(bytes, BASE_PAGE_SIZE) == bytes);
    assert(ROUND_UP(offset, BASE_PAGE_SIZE) == offset);

    errval_t err;

    lvaddr_t l3_addr_start = ROUND_DOWN(addr, VMSAv8_64_L2_BLOCK_SIZE);
    lvaddr_t l3_addr_end = ROUND_UP(addr + bytes, VMSAv8_64_L2_BLOCK_SIZE);

    for (lvaddr_t l3_addr = l3_addr_start; l3_addr < l3_addr_end;
         l3_addr += VMSAv8_64_L2_BLOCK_SIZE) {
        lvaddr_t child_start_vaddr = max(l3_addr, addr);
        lvaddr_t child_end_vaddr = min(l3_addr + VMSAv8_64_L2_BLOCK_SIZE, addr + bytes);
        size_t child_mapping_size = child_end_vaddr - child_start_vaddr;

        // Get the L3 page table node
        struct paging_vnode_node *l3_node = NULL;
        err = lookup_or_create_vnode_node(st, 3, l3_addr, &l3_node);
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
        // FIXME: ret_mapping_cap overwrites
        err = apply_mapping(st, l3_node->vnode_cap, frame, child_start, attr, offset,
                            child_count, ret_mapping_cap);
        if (err_is_fail(err)) {
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
 * @param into_placeholder
 *                Whether going into placeholder. -1: must not. 0: OK. 1: must.
 *
 * @return
 */
static errval_t map_naturally_aligned_fixed(struct paging_state *st, lvaddr_t vaddr,
                                            uint8_t bits, struct capref frame,
                                            size_t bytes, size_t offset, uint64_t attr,
                                            int into_placeholder)
{
#if 0
    DEBUG_PRINTF("map_naturally_aligned_fixed 0x%lx/%lu, offset = 0x%lu\n", vaddr,
                 BIT(bits), offset);
#endif

    assert(bits >= BASE_PAGE_BITS);
    assert((vaddr & MASK(bits)) == 0 && "not naturally aligned");

    errval_t err;

    // Find a free block as small as possible
    for (uint8_t b = bits; b <= PAGING_ADDR_BITS; b++) {
        struct paging_region_node *node = NULL;

        err = lookup_or_create_region_node(st, vaddr & ~MASK(b), b, &node, false);
        if (err_is_ok(err)) {
            if (into_placeholder != 1 && node->free) {
                remove_from_free_list(node);  // refill will not touch it
            } else if (into_placeholder != -1 && node->placeholder) {
                // Keep the property set so that chop_down_region below works correctly
            } else {
                DEBUG_PRINTF("paging: fixed mapping to already used region 0x%lx/%lu, "
                             "free=%d, placeholder=%d\n",
                             node->addr, BIT(node->bits), node->free, node->placeholder);
                return MM_ERR_NOT_FOUND;  // the node is already occupied
            }

            err = chop_down_region(st, &node, vaddr - node->addr, bits);
            if (err_is_fail(err)) {
                return err;
            }

            assert(node->bits == bits && node->addr == vaddr);
            assert(capref_is_null(node->mapping_cap));

            // Actually map the frame, which may span multiple tables
            err = map_frame(st, vaddr, frame, offset, bytes, attr, &node->mapping_cap);
            if (err_is_fail(err)) {
                return err;
            }
            node->placeholder = false;

            assert(!node->free && !node->placeholder);
            // node->mapping_cap may still be NULL_CAP if frame is NULL_CAP (used to
            // create invalid regions)

            return SYS_ERR_OK;

        } else if (err == MM_ERR_FIND_NODE) {
            // Continue to next order
        } else {
            // Other error
            return err;
        }
    }

    DEBUG_PRINTF("paging: run out of memory\n");
    return MM_ERR_NOT_FOUND;
}

static errval_t map_fixed(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                          size_t offset, size_t bytes, uint64_t attr, int into_placeholder)
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
                                              offset + start - vaddr, attr,
                                              into_placeholder);
            if (err_is_fail(err)) {
                return err;
            }
            if (vaddr < start) {
                // Map the heading region
                err = map_fixed(st, vaddr, frame, offset, start - vaddr, attr,
                                into_placeholder);
                if (err_is_fail(err)) {
                    return err;
                }
            }
            if (vaddr + bytes > end) {
                // Map the tailing region
                err = map_fixed(st, end, frame, offset + end - vaddr, vaddr + bytes - end,
                                attr, into_placeholder);
                if (err_is_fail(err)) {
                    return err;
                }
            }
            return SYS_ERR_OK;
        }
    }
    assert(!"paging: should never reach here");
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
 */
static errval_t map_dynamic_using_node(struct paging_state *st, void **buf, uint8_t bits,
                                       struct paging_region_node *node,
                                       struct capref frame, size_t bytes, uint64_t attr)
{
#if 0
    DEBUG_PRINTF("map_dynamic_using_node node=0x%lx << %u, frame bytes = %lu\n",
                 node->addr, node->bits, bytes);
#endif
    errval_t err;

    err = chop_down_region(st, &node, 0, bits);
    if (err_is_fail(err)) {
        return err;
    }
    assert(node->bits == bits);

    if (capref_is_null(frame)) {
        node->placeholder = true;
    } else {
        // Actually map the frame, which may span multiple tables
        err = map_frame(st, node->addr, frame, 0, bytes, attr, &node->mapping_cap);
        if (err_is_fail(err)) {
            return err;
        }
    }

    *buf = (void *)node->addr;
    assert(!node->free);

#if 0
    DEBUG_PRINTF("map_dynamic_using_node gives out 0x%lx/%lu\n", node->addr, bytes);
#endif

    return SYS_ERR_OK;
}

static errval_t map_dynamic(struct paging_state *st, void **buf, size_t bytes,
                            size_t alignment, struct capref frame, uint64_t attr)
{
#if 0
    DEBUG_PRINTF("map_dynamic bytes=%lu, alignment = 0x%lu\n", bytes, alignment);
#endif

    uint8_t bits = max(BASE_PAGE_BITS, log2ceil(bytes));
    uint8_t align_bits = max(BASE_PAGE_BITS, log2ceil(alignment));

    // Fast path: start from align_bits
    for (uint8_t b = max(bits, align_bits); b <= PAGING_ADDR_BITS; b++) {
        if (!LIST_EMPTY(free_list_head(st, b))) {
            struct paging_region_node *node = LIST_FIRST(free_list_head(st, b));
            remove_from_free_list(node);

            return map_dynamic_using_node(st, buf, bits, node, frame, bytes, attr);
        }
    }

    // Slow path: try every available region
    if (bits < align_bits) {
        lvaddr_t align_mask = MASK(align_bits);
        for (uint8_t b = bits; b < align_bits; b++) {
            struct paging_region_node *node = NULL;
            LIST_FOREACH(node, free_list_head(st, b), fl_link)
            {
                if ((node->addr & align_mask) == 0) {
                    remove_from_free_list(node);
                    return map_dynamic_using_node(st, buf, bits, node, frame, bytes, attr);
                }
            }
        }
    }

    // No available region
    return MM_ERR_NOT_FOUND;
}

static inline errval_t assert_arguments(struct paging_state *st, lvaddr_t vaddr,
                                        size_t *size)
{
    if (st == NULL) {
        DEBUG_PRINTF("paging: NULL paging_state\n");
        return ERR_INVALID_ARGS;
    }
    if (vaddr > BIT(PAGING_ADDR_BITS)) {
        DEBUG_PRINTF("paging: vaddr too large\n");
        return ERR_INVALID_ARGS;
    }
    if (*size == 0) {
        DEBUG_PRINTF("paging: cannot map size 0\n");
        return ERR_INVALID_ARGS;
    }
    if (*size >= BIT(PAGING_ADDR_BITS)) {
        DEBUG_PRINTF("paging: size too large\n");
        return ERR_INVALID_ARGS;
    }
    *size = ROUND_UP(*size, BASE_PAGE_SIZE);
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
    st->slot_alloc = ca;

    slab_init(&st->region_slabs, sizeof(struct paging_region_node), slab_default_refill);
    slab_init(&st->vnode_slabs, sizeof(struct paging_vnode_node), slab_default_refill);

    if (!slab_buf_used) {
        // Paging is not setup yet so refill is not available
        slab_grow(&st->region_slabs, slab_buf[0], SLAB_INIT_BUF_SIZE);
        slab_grow(&st->vnode_slabs, slab_buf[1], SLAB_INIT_BUF_SIZE);
        slab_buf_used = true;
    }

    for (int i = 0; i < PAGING_TABLE_LEVELS; i++) {
        RB_INIT(&st->vnode_tree[i]);
    }
    RB_INIT(&st->region_tree);

    for (int i = 0; i < PAGING_ADDR_BITS - BASE_PAGE_BITS + 1; i++) {
        LIST_INIT(&st->free_list[i]);
    }

    st->refilling = false;

    errval_t err;
    struct paging_vnode_node *l0 = NULL;
    err = create_vnode_node(st, 0, 0, &l0);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("paging: failed to create L0 vnode\n")
        return err;
    }
    l0->vnode_cap = pdir;

    struct paging_region_node *init_region = NULL;
    err = create_region_node(st, 0, PAGING_ADDR_BITS, &init_region);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("paging: failed to create L0 region\n")
        return err;
    }
    insert_to_free_list(st, init_region);

    if (start_vaddr > 0) {
        // Grab the region before start_vaddr with attr 0, not actually mapping anything
        err = map_fixed(st, 0, NULL_CAP, 0, start_vaddr, 0, -1 /* must not */);
        if (err_is_fail(err)) {
            DEBUG_PRINTF("paging: failed to grab the region before start_vaddr\n")
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
    debug_printf("paging_init\n");
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
    errval_t err = assert_arguments(st, 0, &bytes);
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
    errval_t err = assert_arguments(st, 0, &bytes);
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
    errval_t err = assert_arguments(st, vaddr, &bytes);
    if (err_is_fail(err)) {
        return err;
    }

    return map_fixed(st, vaddr, frame, 0, bytes, flags_to_attr(flags), 0 /* can */);
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

        err = map_fixed(
            get_current_paging_state(), ROUND_DOWN((lvaddr_t)addr, BASE_PAGE_SIZE), frame,
            0, BASE_PAGE_SIZE, flags_to_attr(VREGION_FLAGS_READ_WRITE), 1 /* must */);
        if (err_is_fail(err)) {
            handle_real_page_fault(type, subtype, addr, regs);
        } else {
            DEBUG_PRINTF("paging: installed page to %p\n", addr);
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
        DEBUG_PRINTF("paging: page fault handler set\n");
    }
    return SYS_ERR_OK;
}