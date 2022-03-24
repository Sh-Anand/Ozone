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

union mm_meta; 

struct mm_entry_meta {
	struct capref map;
	union mm_meta *next;
	int slot;
};

struct mm_vnode_meta {
	struct mm_entry_meta this;
	struct capref cap;
	union mm_meta *first;
	int used; bool blocked;
};

union mm_meta {
	struct mm_entry_meta entry;
	struct mm_vnode_meta vnode;
};
// struct to store the paging status of a process
struct paging_state {
    struct slot_allocator *slot_alloc;
	
	// somewhere there needs to be a structure to keep track of the page table entries
	// I have (sort of) decided that this will happen here for now
	
	//struct m1_page_table_entry *root;
	//struct mm_l0_vnode_meta root_page_tbl;
	struct mm_vnode_meta root;
	
	struct slab_allocator vnode_meta_alloc;
	struct slab_allocator page_meta_alloc;
};


#endif  /// PAGING_TYPES_H_
