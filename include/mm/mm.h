/**
 * \file
 * \brief Memory manager header
 */

/*
 * Copyright (c) 2008, 2011, ETH Zurich.
 * Copyright (c), 2022, The University of British Columbia
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef AOS_MM_H
#define AOS_MM_H

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include "slot_alloc.h"
#include <aos/caddr.h>

__BEGIN_DECLS

/**
 * @brief A struct storing all information required for a memory block.
 *
 */
struct mm_block {
    struct capref root_cap; // The RAM capability the block is a part of (was originally added to the mm)
    gensize_t root_offset; // The offset into the root_cap
    unsigned char size_bits, alignment_bits; // 
};

/**
 * @brief Stores a block together with everything required to store it in either of the data structures
 * 
 */
struct mm_node {
    struct mm_block block;
    struct mm_node *parent; // The node this one resulted from through splitting (or NULL if the block was added during mm_add)
    struct mm_node *left, *right; // In pending tree: left/right child. In free-list: left/right sibling
    capaddr_t key; // Only used in pending tree: contains the key (i.e. reversed capability address of sub cap) associated with this node
    bool is_pending; // True iff element is in pending tree
    bool is_leaf; // True iff element is a leaf (i.e. has not yet been split)
};

/**
 * @brief The number of bits used for physical addresses TODO: Can we get a precise value here (i.e. 48), would lead to nice speedup 
 * 
 */
#define MM_ADDR_BITS (8 * sizeof(genpaddr_t))
#define MM_SLAB_RESERVE (4 * (MM_ADDR_BITS - BASE_PAGE_BITS + 1) + 1) // TODO: precisely determine this value

// Layout a triangle-shaped table to store the linked lists such that we profit from nice locality when walking through the array searching for a suitable block 
#define MM_NODE_TABLE_ROW_OFFSET(block_size_bits) ((MM_ADDR_BITS - (block_size_bits) - 1) * (MM_ADDR_BITS - (block_size_bits)) / 2)
#define MM_NODE_TABLE_COL_OFFSET(alignment_bits) (MM_ADDR_BITS - 1 - (alignment_bits))
#define MM_NODE_TABLE_INDEX(block_size_bits, alignment_bits) (MM_NODE_TABLE_ROW_OFFSET(block_size_bits) + MM_NODE_TABLE_COL_OFFSET(alignment_bits))
#define MM_NODE_TABLE_SIZE MM_NODE_TABLE_ROW_OFFSET(BASE_PAGE_BITS - 1)


/**
 * @brief Reversed 0x00000001, hence half the keys should be smaller and half the keys should be larger than this
 * 
 */
#define MM_PENDING_TREE_PIVOT (0x80000000)


/**
 * \brief Memory manager instance data
 *
 * This should be opaque from the perspective of the client, but to allow
 * them to allocate its memory, we declare it in the public header.
 */
struct mm {
    struct slab_allocator slabs; ///< Slab allocator used for allocating nodes
    slot_alloc_t slot_alloc;     ///< Slot allocator for allocating cspace
    slot_refill_t slot_refill;   ///< Slot allocator refill function
    void *slot_alloc_inst;       ///< Opaque instance pointer for slot allocator
    enum objtype objtype;        ///< Type of capabilities stored
    // TODO: add your meta data tracking here...
    struct mm_node *pending_root; // The root of the pending tree
    struct mm_node *node_table[MM_NODE_TABLE_SIZE]; // The triangle-array storing the linked list of the free nodes
};

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst);
errval_t mm_add(struct mm *mm, struct capref cap);
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                              struct capref *retcap);
errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap);
errval_t mm_free(struct mm *mm, struct capref cap);
void mm_destroy(struct mm *mm);

__END_DECLS

#endif /* AOS_MM_H */
