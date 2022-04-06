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

struct paging_table_node {
    struct capref vnode_cap;
    struct capref array_frame_cap;
    void **children;
};
static_assert(sizeof(struct paging_table_node *) * PTABLE_ENTRIES == BASE_PAGE_SIZE, "children array size");

struct paging_header_node {
    struct capref mapping_cap;
    uint8_t bits;
    bool free;
    lvaddr_t addr;
    LIST_ENTRY(paging_header_node) link;
};

#define PAGING_ADDR_BITS 48

// struct to store the paging status of a process
struct paging_state {
    struct slot_allocator *slot_alloc;
    struct slab_allocator table_slabs;
    struct slab_allocator header_slabs;
    struct paging_table_node *l0;
    LIST_HEAD(, paging_header_node) free_list[PAGING_ADDR_BITS - BASE_PAGE_BITS + 1];
    bool refilling;
    bool booting;
};

#endif  /// PAGING_TYPES_H_
