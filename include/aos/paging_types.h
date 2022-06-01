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

// General node type to work with RB trees
struct paging_rb_tree_node {
    RB_ENTRY(paging_rb_tree_node) rb_entry;
    lvaddr_t addr;
};

RB_HEAD(paging_rb_tree, paging_rb_tree_node);  // tree type declaration

struct paging_vnode_node {
    // "Inherit" struct paging_general_node
    RB_ENTRY(paging_rb_tree_node) rb_entry;
    lvaddr_t addr;
    // Other fields
    struct capref vnode_cap;
    // Mapping cap is discarded now
};

struct paging_region_node {
    // "Inherit" struct paging_general_node
    RB_ENTRY(paging_rb_tree_node) rb_entry;
    lvaddr_t addr;
    // Other fields
    LIST_ENTRY(paging_region_node) fl_link;
    uint8_t bits;
    bool free;
};

struct paging_mapping_child_node {
    LIST_ENTRY(paging_mapping_child_node) link;
    struct capref vnode_cap;
    struct capref mapping_cap;
    struct capref self_paging_frame_cap;
};

struct paging_mapping_node {
    // "Inherit" struct paging_general_node
    RB_ENTRY(paging_rb_tree_node) rb_entry;
    lvaddr_t addr;
    // Other fields
    LIST_HEAD(paging_mapping_node_head, paging_mapping_child_node) mappings;
    struct paging_region_node *region;
};

// struct to store the paging status of a process
struct paging_state {
    struct paging_rb_tree vnode_tree[PAGING_TABLE_LEVELS];
    struct paging_rb_tree region_tree;
    struct paging_rb_tree mapping_tree;
    struct slot_allocator *slot_alloc;
    struct slab_allocator vnode_slabs;
    struct slab_allocator region_slabs;
    struct slab_allocator mapping_node_slabs;
    struct slab_allocator mapping_child_slabs;
    struct thread_mutex frame_alloc_mutex;
    struct thread_mutex free_list_mutex;
    LIST_HEAD(paging_free_list_head, paging_region_node) free_list[PAGING_ADDR_BITS - BASE_PAGE_BITS + 1];
    lvaddr_t start_addr;
    bool refilling;
};

#endif  /// PAGING_TYPES_H_
