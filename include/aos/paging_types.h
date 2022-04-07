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

#define VADDR_OFFSET ((lvaddr_t)512UL*1024*1024*1024) // 1GB
#define VREGION_FLAGS_READ     0x01 // Reading allowed
#define VREGION_FLAGS_WRITE    0x02 // Writing allowed
#define VREGION_FLAGS_EXECUTE  0x04 // Execute allowed
#define VREGION_FLAGS_NOCACHE  0x08 // Caching disabled
#define VREGION_FLAGS_MPB      0x10 // Message passing buffer
#define VREGION_FLAGS_GUARD    0x20 // Guard page
#define VREGION_FLAGS_MASK     0x2f // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE \
   (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE \
   (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE \
   (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB \
   (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)

typedef int paging_flags_t;


struct paging_node {
   size_t index;
   uint16_t count;
   bool is_placeholder;
   bool is_invalid;
   struct capref vnode_cap;
   // XXX: for now the mapping cap is not tracked
   size_t max_continuous_count;  // largest continuous region, 0 and empty children means invalid
   LIST_HEAD(, paging_node) children;
   LIST_ENTRY(paging_node) link;
};

// struct to store the paging status of a process
struct paging_state {
   struct slot_allocator *slot_alloc;
   struct slab_allocator slabs;
   struct paging_node *l0;
   bool refilling;
};


#endif  /// PAGING_TYPES_H_
