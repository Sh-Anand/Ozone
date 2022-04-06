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

#define PAGING_STATIC_PAGE_COUNT 8
static char static_page[PAGING_STATIC_PAGE_COUNT][BASE_PAGE_SIZE];
static int used_static_page_count = 0;

#define SLAB_INIT_BUF_SIZE 8192
static char slab_buf[2][SLAB_INIT_BUF_SIZE];
static bool slab_buf_used = false;

#define SLAB_REFILL_THRESHOLD 12

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

static inline unsigned char __ceil_block_size2_bits(size_t block_size)
{
    assert(block_size > 1);
    return (PAGING_ADDR_BITS - __builtin_clzl(block_size - 1));
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

    assert(end_index > start_index);
    assert(start_index < 512);
    assert(end_index <= 512);
    assert((end_index - start_index) * CHILD_SIZE >= bytes);

    *ret_inclusive_start = start_index;
    *ret_exclusive_end = end_index;
    *ret_count = end_index - start_index;
}

static inline errval_t alloc_zeroed_frame(struct paging_state *st, size_t bytes,
                                          struct capref *frame_cap, void **vaddr)
{
    assert(vaddr != NULL);
    errval_t err;

    if (used_static_page_count < PAGING_STATIC_PAGE_COUNT) {
        assert(bytes == BASE_PAGE_SIZE);
        *vaddr = static_page[used_static_page_count++];
        memset((*vaddr), 0, BASE_PAGE_SIZE);
        return SYS_ERR_OK;
    }

    // Create the frame
    struct capref frame;
    err = frame_alloc(&frame, bytes, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // Map the frame
    void *handle = NULL;
    err = paging_map_frame(st, &handle, bytes, frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP);
    }
    assert(handle != NULL);

    // Zero the frame
    memset((void *)handle, 0, bytes);

    if (frame_cap != NULL) {
        *frame_cap = frame;
    }
    *vaddr = handle;
    return SYS_ERR_OK;
}

// For mapping either frame or vnode in vnode
static inline errval_t apply_mapping(struct paging_state *st, struct capref dest,
                                     struct capref src, capaddr_t slot, uint64_t attr,
                                     uint64_t off, uint64_t pte_count,
                                     struct capref *ret_mapping_cap)
{
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

static inline void insert_to_free_list(struct paging_state *st,
                                       struct paging_header_node *node)
{
    assert(!node->free);
    assert(node->bits >= BASE_PAGE_BITS && node->bits <= PAGING_ADDR_BITS);
    LIST_INSERT_HEAD(&st->free_list[node->bits - BASE_PAGE_BITS], node, link);
    node->free = true;
}

static inline void remove_from_free_list(struct paging_header_node *node)
{
    assert(node->free);
    node->free = false;
    LIST_REMOVE(node, link);
}

// Create a node. cap is initialized to NULL_CAP. link is not initialized
static inline errval_t alloc_table_node(struct paging_state *st,
                                        struct paging_table_node **ret)
{
    struct paging_table_node *n = slab_alloc(&st->table_slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    memset(n, 0, sizeof(*n));  // NULL_CAP is all 0
    *ret = n;
    return SYS_ERR_OK;
}

static inline errval_t create_and_install_table_node(struct paging_state *st,
                                                     size_t level, size_t index,
                                                     struct capref parent_cap,
                                                     struct paging_table_node **node_ptr)
{
    if (*node_ptr == NULL) {
        errval_t err;
        HERE;
        // Create the table node
        err = alloc_table_node(st, node_ptr);
        if (err_is_fail(err)) {
            return err;
        }
        HERE;
        // Create the page table
        err = pt_alloc(st, CHILD_PAGE_TABLE_TYPE[level], &(*node_ptr)->vnode_cap);
        if (err_is_fail(err)) {
            return err;
        }
        HERE;
        // Install the page table
        err = apply_mapping(st, parent_cap, (*node_ptr)->vnode_cap, index,
                            KPI_PAGING_FLAGS_READ | KPI_PAGING_FLAGS_WRITE, 0, 1, NULL);
        if (err_is_fail(err)) {
            return err;
        }
        HERE;
        // Its children will be allocated lazily using lazy_alloc_child_array
    }
    return SYS_ERR_OK;
}

// free initialized to false
static inline errval_t alloc_header_node(struct paging_state *st, lvaddr_t addr,
                                         uint8_t bits, struct paging_header_node **ret)
{
    struct paging_header_node *n = slab_alloc(&st->header_slabs);
    if (n == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    n->addr = addr;
    n->bits = bits;
    n->free = false;
    *ret = n;
    return SYS_ERR_OK;
}

static inline errval_t lazy_alloc_child_array(struct paging_state *st,
                                              struct paging_table_node *node)
{
    if (node->children == NULL) {
        assert(capref_is_null(node->array_frame_cap));
        return alloc_zeroed_frame(st, BASE_PAGE_SIZE, &node->array_frame_cap,
                                  (void **)&node->children);
        assert(node->children != NULL);
    }
    return SYS_ERR_OK;
}

static errval_t _lookup_or_create_node(struct paging_state *st,
                                       struct paging_table_node *node, size_t level,
                                       lvaddr_t rvaddr, lvaddr_t vaddr,
                                       struct paging_header_node **ret,
                                       uint8_t create_bits)
{
    assert(level <= 3);
    assert(node);
    assert(ROUND_UP(rvaddr, BASE_PAGE_SIZE) == rvaddr);
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];

    errval_t err;

    size_t i = get_child_index(rvaddr, level);

#if 1
    debug_printf("_lookup_or_create_node(%lu) 0x%lx (relative 0x%lx) %s%d, i = %lu\n", level,
                 vaddr, rvaddr, create_bits != 0 ? "create " : "lookup ", create_bits, i);
#endif

    // Lazy allocation
    err = lazy_alloc_child_array(st, node);
    if (err_is_fail(err)) {
        return err;
    }
    HERE;
    if (level < 3) {
        struct paging_table_node **children = (struct paging_table_node **)node->children;
        HERE;
        if (children[i] == NULL && create_bits > 0) {
            HERE;
            err = create_and_install_table_node(st, level, i, node->vnode_cap,
                                                &children[i]);
            HERE;
            if (err_is_fail(err)) {
                return err;
            }
        } else {
            *ret = NULL;
            return MM_ERR_FIND_NODE;
        }
        HERE;
        // Relative to this node
        lvaddr_t next_rvaddr = max(i * CHILD_SIZE, rvaddr) - (i * CHILD_SIZE);

        return _lookup_or_create_node(st, children[i], level + 1, next_rvaddr, vaddr, ret,
                                      create_bits);

    } else {
        struct paging_header_node **children
            = (struct paging_header_node **)node->children;

        if (children[i] == NULL && create_bits > 0) {
            err = alloc_header_node(st, vaddr, create_bits, &children[i]);
            if (err_is_fail(err)) {
                return err;
            }
        }

        if (children[i] == NULL) {
            *ret = NULL;
            return MM_ERR_FIND_NODE;
        } else {
            *ret = children[i];
            return SYS_ERR_OK;
        }
    }
}

static inline errval_t lookup_or_create_node(struct paging_state *st, lvaddr_t vaddr,
                                             uint8_t bits,
                                             struct paging_header_node **ret, bool create)
{
    errval_t err = _lookup_or_create_node(st, st->l0, 0, vaddr, vaddr, ret,
                                          (create ? bits : 0));
    if (err_is_fail(err)) {
        return err;
    }
    if (*ret) {
        assert((*ret)->bits == bits);
        assert((*ret)->addr == vaddr);
    }
    return SYS_ERR_OK;
}

static errval_t chop_down_region(struct paging_state *st,
                                 struct paging_header_node **node_ptr, lvaddr_t rvaddr,
                                 uint8_t bits)
{
    struct paging_header_node *node = *node_ptr;
    assert(!node->free);
    assert(node->bits >= bits);

    errval_t err;

    while (node->bits > bits) {
        // Downgrade to next level
        node->bits--;
        struct paging_header_node *left = node;

        // Create buddy node
        struct paging_header_node *right = NULL;
        err = lookup_or_create_node(st, left->addr | BIT(left->bits), left->bits, &right,
                                    true);
        if (err_is_fail(err)) {
            return err;
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

// This function is still needed since a mapping can span multiple tables
static errval_t map_frame_recursive(struct paging_state *st,
                                    struct paging_table_node *node, size_t level,
                                    lvaddr_t rvaddr, struct capref frame, size_t offset,
                                    size_t bytes, uint64_t attr)
{
    assert(level <= 3 && "paging: invalid level");
    assert(ROUND_UP(bytes, BASE_PAGE_SIZE) == bytes);
    assert(ROUND_UP(offset, BASE_PAGE_SIZE) == offset);
    assert(!capref_is_null(node->vnode_cap));

    errval_t err;
    const size_t CHILD_SIZE = CHILD_BLOCK_SIZE[level];
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

    // Lazy allocation
    err = lazy_alloc_child_array(st, node);
    if (err_is_fail(err)) {
        return err;
    }


    if (level < 3) {
        struct paging_table_node **children = (struct paging_table_node **)node->children;

        for (size_t i = child_start; i < child_end; i++) {
            if (children[i] == NULL) {
                err = create_and_install_table_node(st, level, i, node->vnode_cap,
                                                    &children[i]);
                if (err_is_fail(err)) {
                    return err;
                }
            }

            // Relative to this node
            lvaddr_t child_start_vaddr = max(i * CHILD_SIZE, rvaddr);
            lvaddr_t child_end_vaddr = min((i + 1) * CHILD_SIZE, rvaddr + bytes);
            size_t child_mapping_size = child_end_vaddr - child_start_vaddr;
            assert(child_mapping_size <= CHILD_SIZE);

            lvaddr_t next_rvaddr = child_start_vaddr - (i * CHILD_SIZE);

            err = map_frame_recursive(st, children[i], level + 1, next_rvaddr, frame,
                                      offset, child_mapping_size, attr);
            if (err_is_fail(err)) {
                return err;
            }

            offset += child_mapping_size;
        }

    } else {
        // Actually apply the mapping, all at once

        struct paging_header_node **children
            = (struct paging_header_node **)node->children;
        assert(children[child_start] != NULL);
        assert(BIT(children[child_start]->bits) == bytes);

        err = apply_mapping(st, node->vnode_cap, frame, child_start, attr, offset,
                            child_count, &children[child_start]->mapping_cap);
        if (err_is_fail(err)) {
            return err;
        }
    }

    return SYS_ERR_OK;
}

static errval_t map_naturally_aligned_fixed(struct paging_state *st, lvaddr_t vaddr,
                                            uint8_t bits, struct capref frame,
                                            size_t offset, uint64_t attr)
{
    assert(bits >= BASE_PAGE_BITS);
    assert((vaddr & MASK(bits)) == 0 && "not naturally aligned");

    errval_t err;

    // Find a free block as small as possible
    for (uint8_t b = bits; b <= PAGING_ADDR_BITS; b++) {
        struct paging_header_node *node = NULL;

        // Will not trigger refill
        err = lookup_or_create_node(st, vaddr & ~MASK(b), b, &node, true);
        if (err_is_ok(err)) {
            assert(node != NULL);
            if (!node->free) {
                return MM_ERR_NOT_FOUND;
            }

            remove_from_free_list(node);  // refill will not touch it

            err = chop_down_region(st, &node, vaddr - node->addr, bits);
            if (err_is_fail(err)) {
                return err;
            }

            assert(node->bits == bits);
            assert(node->addr == vaddr);
            assert(capref_is_null(node->mapping_cap));

            // Actually map the frame, which may span multiple tables
            err = map_frame_recursive(st, st->l0, 0, vaddr, frame, offset, BIT(bits),
                                      attr);
            if (err_is_fail(err)) {
                return err;
            }

            assert(!capref_is_null(node->mapping_cap));  // should touch node

            return SYS_ERR_OK;
        } else if (err == MM_ERR_FIND_NODE) {
            // Continue to next order
        } else {
            // Other error
            return err;
        }
    }
    return MM_ERR_NOT_FOUND;
}

static errval_t map_fixed(struct paging_state *st, lvaddr_t vaddr, struct capref frame,
                          size_t offset, size_t bytes, uint64_t attr)
{
    assert(bytes == ROUND_UP(bytes, BASE_PAGE_SIZE));

    errval_t err;

    for (uint8_t bits = log2floor(bytes); bits >= VMSAv8_64_BASE_PAGE_BITS; bits--) {
        const lvaddr_t BLOCK_SIZE = BIT(bits);
        lvaddr_t start = ROUND_UP(vaddr, BLOCK_SIZE);  // naturally aligned
        lvaddr_t end = start + BLOCK_SIZE;
        if (end <= vaddr + bytes) {
            // Mapp the region
            err = map_naturally_aligned_fixed(st, start, bits, frame,
                                              offset + start - vaddr, attr);
            if (err_is_fail(err)) {
                return err;
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
    assert(!"should not reach here");
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

    st->booting = true;
    st->slot_alloc = ca;

    slab_init(&st->header_slabs, sizeof(struct paging_header_node), slab_default_refill);
    slab_init(&st->table_slabs, sizeof(struct paging_table_node), slab_default_refill);

    if (!slab_buf_used) {
        // Paging is not setup yet so refill is not available
        slab_grow(&st->header_slabs, slab_buf[0], SLAB_INIT_BUF_SIZE);
        slab_grow(&st->table_slabs, slab_buf[1], SLAB_INIT_BUF_SIZE);
        slab_buf_used = true;
    }

    errval_t err;
    err = alloc_table_node(st, &st->l0);
    if (err_is_fail(err)) {
        return err;
    }
    st->l0->vnode_cap = pdir;
    st->l0->children = (void **)static_page[used_static_page_count++];

    struct paging_table_node *table_node = st->l0;
    for (int i = 1; i <= 3; i++) {
        struct paging_table_node *new_table_node;
        err = alloc_table_node(st, &new_table_node);
        if (err_is_fail(err)) {
            return err;
        }
        new_table_node->children = (void **)static_page[used_static_page_count++];
        table_node->children[0] = new_table_node;
        table_node = new_table_node;
    }

    // Create header node for the whole virtual address space
    struct paging_header_node *l0_header = NULL;
    err = alloc_header_node(st, 0, PAGING_ADDR_BITS, &l0_header);
    if (err_is_fail(err)) {
        return err;
    }
    table_node->children[0] = l0_header;
    insert_to_free_list(st, l0_header);

    st->refilling = false;
    st->booting = false;
    //
    //    // TODO: for now just handle the only case of skipping first L1
    //    if (start_vaddr == VMSAv8_64_L0_SIZE) {
    //        struct paging_header_node *first_l1;
    //        err = create_node(st, 0, 1, &first_l1);
    //        if (err_is_fail(err)) {
    //            return err;
    //        }
    //        first_l1->max_continuous_count = 0;  // invalid
    //        assert(LIST_EMPTY(&first_l1->children));
    //
    //        LIST_INSERT_HEAD(&st->l0->children, first_l1, link);
    //        st->l0->max_continuous_count--;
    //    }

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
    // TODO (M4):
    //   - setup exception handler for thread `t'.
    return LIB_ERR_NOT_IMPLEMENTED;
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
    return LIB_ERR_NOT_IMPLEMENTED;
    //    return map_recursive(st, st->l0, 0, 0, NULL_CAP, 0, ROUND_UP(bytes,
    //    BASE_PAGE_SIZE),
    //                         0, (lvaddr_t *)buf);
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

    return LIB_ERR_NOT_IMPLEMENTED;
    //    return map_recursive(st, st->l0, 0, 0, frame, 0, ROUND_UP(bytes, BASE_PAGE_SIZE),
    //                         flags_to_attr(flags), (lvaddr_t *)buf);
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

    return map_fixed(st, vaddr, frame, 0, bytes, flags_to_attr(flags));
    //    return map_recursive(st, st->l0, 0, vaddr, frame, 0, ROUND_UP(bytes,
    //    BASE_PAGE_SIZE),
    //                         flags_to_attr(flags), NULL);
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

static void page_fault_handler(enum exception_type type, int subtype, void *addr,
                               arch_registers_state_t *regs)
{
    if (type == EXCEPT_PAGEFAULT) {
        DEBUG_PRINTF("Page fault! subtype = %d, addr = %p\n", subtype, addr);

        if (addr == NULL) {
            DEBUG_PRINTF("NULL pointer\n", subtype, addr);
            exit(EXIT_FAILURE);
        }

        errval_t err;
        struct capref frame = NULL_CAP;

        err = frame_alloc(&frame, BASE_PAGE_SIZE, NULL);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_page_fault_handler: frame_alloc failed\n");
        }

        err = paging_map_fixed(get_current_paging_state(),
                               ROUND_DOWN((lvaddr_t)addr, BASE_PAGE_SIZE), frame,
                               BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "paging_page_fault_handler: paging_map_fixed failed\n");
        }
    }
}

static errval_t set_page_fault_handler(void)
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