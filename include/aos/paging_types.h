/**
 * \file
 * \brief PMAP Implementaiton for AOS
 */

/*
 * Copyright (c) 2019 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef PAGING_TYPES_H_
#define PAGING_TYPES_H_ 1

#include <aos/solution.h>
#include <sys/queue.h>
#include <sys/tree.h>

#define VADDR_OFFSET ((lvaddr_t)512UL * 1024 * 1024 * 1024)  // 1GB
#define VREGION_FLAGS_READ 0x01                              // Reading allowed
#define VREGION_FLAGS_WRITE 0x02                             // Writing allowed
#define VREGION_FLAGS_EXECUTE 0x04                           // Execute allowed
#define VREGION_FLAGS_NOCACHE 0x08                           // Caching disabled
#define VREGION_FLAGS_MPB 0x10                               // Message passing buffer
#define VREGION_FLAGS_GUARD 0x20                             // Guard page
#define VREGION_FLAGS_MASK 0x2f  // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE                                                 \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB                                                     \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)

typedef int paging_flags_t;

#define PAGING_ADDR_BITS 48
#define PAGING_TABLE_LEVELS 4

struct paging_vnode_node {
    RB_ENTRY(paging_vnode_node) rb_entry;
    struct capref vnode_cap;
    struct capref mapping_cap;
    lvaddr_t addr;
};

int	paging_vnode_node_cmp(struct paging_vnode_node *, struct paging_vnode_node *);

struct paging_region_node {
    RB_ENTRY(paging_region_node) rb_entry;
    LIST_ENTRY(paging_region_node) fl_link;
    struct capref mapping_cap;
    lvaddr_t addr;
    uint8_t bits;
    bool free;
    bool placeholder;
};

int	paging_region_node_cmp(struct paging_region_node *, struct paging_region_node *);

// struct to store the paging status of a process
struct paging_state {
    RB_HEAD(vnode_tree, paging_vnode_node) vnode_tree[PAGING_TABLE_LEVELS];
    RB_HEAD(region_tree, paging_region_node) region_tree;
    struct slot_allocator *slot_alloc;
    struct slab_allocator vnode_slabs;
    struct slab_allocator region_slabs;
    LIST_HEAD(paging_free_list_head, paging_region_node) free_list[PAGING_ADDR_BITS - BASE_PAGE_BITS + 1];
    bool refilling;
};

#endif  /// PAGING_TYPES_H_
