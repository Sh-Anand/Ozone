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

static struct paging_state current;
static int slab_vnode_refilling = 0;
static int slab_page_refilling = 0;

#define SLAB_REFILL_THRESHOLD 32
#define SLAB_INIT_BUF_LEN 65536 // for starting out, 64kB should be enough for the memory manager to begin mapping some pages
static char slab_vnode_init_buf[SLAB_INIT_BUF_LEN];
static char slab_page_init_buf[SLAB_INIT_BUF_LEN];

const static enum objtype vnode_types[3] = { ObjType_VNode_AARCH64_l1, ObjType_VNode_AARCH64_l2, ObjType_VNode_AARCH64_l3 };

/**
 * @brief Small utility function to refill a slab allocator
 * 
 * @param refilling a reference to the flag prohibiting nested refills
 * @param slabs a slab allocator reference
 * @return errval_t 
 */
static inline errval_t refill_slab_alloc(int *refilling, struct slab_allocator *slabs) {
	if (!(*refilling) && slab_freecount(slabs) < SLAB_REFILL_THRESHOLD) {
		*refilling = 1;
		errval_t e = slabs->refill_func(slabs);
		if (err_is_fail(e)) {
			DEBUG_ERR(e, "slab refilling failed");
		}
		*refilling = 0;
		return e;
	}
	
	return SYS_ERR_OK;
}

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state * st, enum objtype type, 
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

static errval_t rec_map_fixed(struct paging_state *st, struct mm_vnode_meta *root, lvaddr_t rvaddr, size_t size, struct capref frame, size_t frame_offset, uint64_t flags, int depth) {
	// declare and define necessary variables
	assert(rvaddr % BASE_PAGE_SIZE == 0);
	assert(size % BASE_PAGE_SIZE == 0);
	errval_t err;
	capaddr_t start, end;
	size_t bit_offset = 39 - 9*depth;
	size_t sub_region_size = 1UL << bit_offset;
	start = rvaddr >> (39 - depth*9);
	end = (rvaddr + size - 1) >> (39 - depth*9);
	printf("%ld, %ld, %ld, %ld, %d\n", rvaddr, size, frame_offset, sub_region_size, depth);
	printf("%i, %i\n", start, end);
	assert(start < 512 && end < 512);
	
	union mm_meta **pointer_to_current_meta = &(root->first); // this tracks the address of the pointer we need to write
	union mm_meta *current_meta = root->first; // this tracks the current_meta page table entry while walking through the list
	
	for (int i = start; i <= end; i++) {
		// walk through the list until current_meta is either the required entry, or the first entry after the point of insertion
		while (current_meta != NULL && current_meta->entry.slot < i) {
			pointer_to_current_meta = &(current_meta->entry.next);
			current_meta = current_meta->entry.next;
		}
		
		// check if we found the necessary entry
		if (current_meta == NULL || current_meta->entry.slot != i) {
			// declare necessary variables
			union mm_meta *new_entry; //
			struct capref mapee;
			size_t off;
			
			if (depth < 3) {
				// this is another vnode to create
				new_entry = slab_alloc(&(st->vnode_meta_alloc)); // allocate space for another struct mm_vnode_meta
				new_entry->vnode.used = 0;
				err = pt_alloc(st, vnode_types[depth], &(new_entry->vnode.cap));
				if (err_is_fail(err)) {
					DEBUG_ERR(err, "pt_alloc failed");
					return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
				}
				mapee = new_entry->vnode.cap; // a new vnode has to be mapped
				off = 0; // there is no offset for vnodes
			} else {
				// this is a page entry to create
				new_entry = slab_alloc(&(st->page_meta_alloc)); // allocate space for another struct mm_entry_meta
				mapee = frame; // the frame is to be mapped here
				off = frame_offset + (i - start) * sub_region_size; // pages have a necessary frame offset if more than a single page is mapped
				//printf("Mapped %i/%i: %i\n", i, end, off);
			}
			
			new_entry->entry.slot = i; // set the slot of the new element
			new_entry->entry.next = current_meta; // set the next pointer of the new element
			*pointer_to_current_meta = new_entry; // link the new element into the list
			
			// allocate the mapping capability
			err = st->slot_alloc->alloc(st->slot_alloc, &(new_entry->entry.map));
			if (err_is_fail(err)) {
				DEBUG_ERR(err, "slot_alloc failed");
				if (depth < 3) st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
			}
			
			// map the page
			//debug_printf("mapee croot: %p, roots croot(dest): %p\n", get_croot_addr(mapee), get_croot_addr(root->cap));
			//debug_printf("st->root: %p\n", get_croot_addr(st->root.cap));
			err = vnode_map(root->cap, mapee, i, flags, off, 1 /* for now we only map one page at a time in all cases */, new_entry->entry.map);
			if (err_is_fail(err)) {
				DEBUG_ERR(err, "vnode_map failed");
				st->slot_alloc->free(st->slot_alloc, new_entry->entry.map);
				st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
			}
			
			// update current_meta to be used later
			current_meta = new_entry;
		} else {
			assert(depth < 3);
			assert(current_meta->vnode.used < 512);
		}
				
		if (depth < 3) {
			// this is not the last level page table, so continue with the next layer
			long next_size = sub_region_size;
			if (i == start) next_size = sub_region_size - rvaddr % sub_region_size;
			if (i == end) next_size = (rvaddr + size - 1) % sub_region_size + 1;
			if (i == start && i == end) next_size = size;

			current_meta->vnode.blocked = true;
			err = rec_map_fixed(st, &current_meta->vnode, i == start ? rvaddr % sub_region_size : 0, next_size, frame, i == start ? frame_offset : frame_offset + (sub_region_size - rvaddr % sub_region_size) +  (i - start - 1) * sub_region_size, flags, depth + 1);
			current_meta->vnode.blocked = false;
			if (err_is_fail(err)) {
				// TODO: verify no cleanup needed
				DEBUG_ERR(err, "failed to map fixed address");
				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
			}
		}
	}

	root->used += end - start + 1;
	assert(root->used <= VMSAv8_64_PTABLE_NUM_ENTRIES);
	
	return SYS_ERR_OK;
}

inline int lower_bound_empty_subsequent_blocks(int used) {
	assert(used >= 0 && used <= VMSAv8_64_PTABLE_NUM_ENTRIES);
	return VMSAv8_64_PTABLE_NUM_ENTRIES / (used + 1);
}

//errval_t rec_map(struct paging_state *st, struct mm_vnode_meta *root, size_t size, struct capref frame, void** buf, lvaddr_t base_addr, size_t frame_offset, uint64_t flags, int depth);
// static errval_t rec_map(struct paging_state *st, struct mm_vnode_meta *root, size_t size, struct capref frame, void** buf, lvaddr_t base_addr, size_t frame_offset, uint64_t flags, int depth) {
// 	assert(rvaddr % BASE_PAGE_SIZE == 0);
// 	assert(size % BASE_PAGE_SIZE == 0);
	
// 	// simple approach for now: just find the first fitting region
	
// 	// declare and define some necessary variables
// 	errval_t err;
	
// 	lvaddr_t out_addr = 0;
// 	size_t bit_offset = 39 - 9*depth;
// 	size_t sub_region_size = 1UL << bit_offset;
// 	size_t next_sub_region_size = 1UL << (bit_offset - 9);
	
// 	int n_free_blocks = lower_bound_empty_subsequent_blocks(root->used);
// 	int n_blocks_necessary = (size + sub_region_size - 1) / sub_region_size;
// 	int n_next_blocks_necessary = (size + next_sub_region_size - 1) / next_sub_region_size;
	
	
// 	//printf("size %ld, bit_offset %ld, sub_region_size %ld, depth %ld, flags %ld, base_addr %ld\n", size, bit_offset, sub_region_size, depth, flags, base_addr);
	
// 	// small sanity check: if there is not enough space here, then something is not right
// 	assert(size <= sub_region_size * n_free_blocks); // this right?
	
// 	union mm_meta **pointer_to_current_meta = &(root->first); // this tracks the address of the pointer we need to write
// 	union mm_meta *current_meta = root->first; // this tracks the current_meta page table entry while walking through the list
// 	int last_slot = 0; // keep track of the beginning of the free region delimited by current

// 	// find a large enough free region, this should always be possible here
// 	if (depth < 3 && n_blocks_necessary == 1) { // only one block is necessary, so it is possible to reuse an already mapped vnode if it has enough children
// 		while (current_meta != NULL && (lower_bound_empty_subsequent_blocks(current_meta->vnode.used) < n_next_blocks_necessary || current_meta->vnode.blocked)) {
// 			last_slot = current_meta->entry.slot + 1; // the next iteration should have a look at the region starting after the current slot
// 			pointer_to_current_meta = &(current_meta->entry.next);
// 			current_meta = current_meta->entry.next;
// 		}
// 		// current is either NULL or the desired vnode
// 		if (current_meta != NULL) {
// 			//debug_printf("non mapped\n");
			
// 			current_meta->vnode.blocked = true;
// 			err = rec_map(st, &(current_meta->vnode), rvaddr % sub_region_size, frame, buf, base_addr + current_meta->entry.slot * sub_region_size, frame_offset, flags, depth + 1);
// 			current_meta->vnode.blocked = false;
// 			if (err_is_fail(err)) {
// 				DEBUG_ERR(err, "allocation of virtual addresses failed");
// 				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
// 			}
// 			return SYS_ERR_OK;
// 		} else {
// 			pointer_to_current_meta = &(root->first);
// 			current_meta = root->first;
// 			last_slot = 0;
// 			goto new_mapping;
// 		}
// 	} else { // if either multiple tables are needed or we are at a leaf node, just find the first suitable region
// 		//debug_printf("starting while\n");
// 		new_mapping:
// 		while (current_meta != NULL && current_meta->entry.slot - last_slot < n_blocks_necessary) {
// 			//debug_printf("current: %p, slot: %d: next: %p\n", current_meta, current_meta->entry.slot, current_meta->entry.next);
// 			last_slot = current_meta->entry.slot + 1; // the next iteration should have a look at the region starting after the current slot
// 			pointer_to_current_meta = &(current_meta->entry.next);
// 			current_meta = current_meta->entry.next;
// 		}
		
// 		debug_printf("last_slot: %d, current: %p, current->slot: %d, current_p: %p\n", last_slot, current_meta, current_meta ? current_meta->entry.slot : -1, pointer_to_current_meta);
// 		//fflush(stdout);
// 		debug_printf("nec. blocks: %d\n", n_blocks_necessary);
	
// 		// there should now be space for the necessary mappings, so insert them now
// 		// at this point, current should be the first element after the insertion
// 		for (int i = 0; i < n_blocks_necessary; i++) {
// 			//debug_printf("%d/%d\n", i, n_blocks_necessary);
// 			union mm_meta *new_entry;
			
// 			struct capref mapee;
// 			size_t off;
			
// 			if (depth < 3) {
// 				// this is another vnode to create
// 				new_entry = slab_alloc(&(st->vnode_meta_alloc)); // allocate space for another struct mm_vnode_meta
// 				new_entry->vnode.used = 0;
// 				err = pt_alloc(st, vnode_types[depth], &(new_entry->vnode.cap));
// 				if (err_is_fail(err)) {
// 					DEBUG_ERR(err, "pt_alloc failed");
// 					return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
// 				}
// 				mapee = new_entry->vnode.cap; // a new vnode has to be mapped
// 				off = 0; // there is no offset for vnodes
// 			} else {
// 				// this is a page entry to create
// 				new_entry = slab_alloc(&(st->page_meta_alloc)); // allocate space for another struct mm_entry_meta
// 				mapee = frame; // the frame is to be mapped here
// 				off = frame_offset + (i - start) * sub_region_size; // pages have a necessary frame offset if more than a single page is mapped
// 			}
			
// 			// initialize the entry
// 			new_entry->entry.slot = last_slot + i;
// 			new_entry->entry.next = current_meta;
// 			*pointer_to_current_meta = new_entry;
// 			pointer_to_current_meta = &(new_entry->entry.next);
			
// 			// allocate the mapping capability
// 			err = st->slot_alloc->alloc(st->slot_alloc, &(new_entry->entry.map));
// 			if (err_is_fail(err)) {
// 				DEBUG_ERR(err, "slot_alloc failed");
// 				if (depth < 3) st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
// 				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
// 			}
			
// 			// map the page
// 			err = vnode_map(root->cap, mapee, last_slot + i, flags, off /* TODO: verify the offset */, 1 /* for now we only map one page at a time in all cases */, new_entry->entry.map);
// 			//debug_printf("mapping of slot %d at depth %d in pt %p failed\n", last_slot + i, depth, get_cap_addr(root->cap));
// 			if (err_is_fail(err)) {
// 				DEBUG_ERR(err, "vnode_map failed");
// 				st->slot_alloc->free(st->slot_alloc, new_entry->entry.map);
// 				st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
// 				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
// 			}
			
// 			// descend and map the children of this new entry (only needs to happen for vnodes, not for pages)
// 			if (depth < 3) {
// 				lvaddr_t ra;
// 				err = rec_map(st, &(new_entry->vnode), MIN(sub_region_size, size - i*sub_region_size), frame, (void**)&ra, base_addr + new_entry->entry.slot*sub_region_size, frame_offset + i*sub_region_size, flags, depth+1);
// 				if (err_is_fail(err)) {
// 					// TODO: perform possible and necessary cleanup here
// 					DEBUG_ERR(err, "rec_map failed");
// 					return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
// 				}
// 				if (i == 0) {
// 					//debug_printf("ra: %ld\n", ra);
// 					out_addr = ra; // set base_addr to first mapped address in this sub tree (only in the first iteration)
// 				}
// 			} else {
// 				if (i == 0) out_addr = base_addr + (last_slot + i) * 4096;
// 			}
// 		}
		
// 		// since weded need to map new vnodes, update the used count of the root node of this subtree
// 		root->used += n_blocks_necessary; 
// 	}
	
// 	//printf("out_addr %ld\n", out_addr);
	
// 	// return the mapped address
// 	*buf = (void*)out_addr;
	
// 	return SYS_ERR_OK;
// }

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
	printf("Init non-foreign %p %p\n", &st->vnode_meta_alloc, &st->page_meta_alloc);
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
	
	// TODO: react to start_vaddr
	
	st->slot_alloc = ca;
	
	// initialize and grow the slab allocators for struct mm_entry_meta and struct mm_vnode_meta
	slab_init(&(st->vnode_meta_alloc), sizeof(struct mm_vnode_meta), slab_default_refill);
	slab_grow(&(st->vnode_meta_alloc), slab_vnode_init_buf, SLAB_INIT_BUF_LEN);
	
	slab_init(&(st->page_meta_alloc), sizeof(struct mm_entry_meta), slab_default_refill);
	slab_grow(&(st->page_meta_alloc), slab_page_init_buf, SLAB_INIT_BUF_LEN);
	
	// XXX: temporary fix, but occupy the first L0 slot since mappings in there tend to be taken already
	union mm_meta *slot0 = slab_alloc(&(st->vnode_meta_alloc));
	slot0->entry.slot = 0;
	slot0->vnode.used = 512;
	slot0->entry.next = NULL;
	slot0->vnode.first = NULL;
	
	assert(get_croot_addr(pdir) == CPTR_ROOTCN);
	
	// populate the root vnode
	st->root.cap = pdir;
	st->root.first = slot0;
	st->root.this.map = NULL_CAP;
	st->root.this.next = NULL;
	st->root.this.slot = -1;
	st->root.used = 1;
	st->offset = 10UL << 39;
	
	assert(get_croot_addr(st->root.cap) == CPTR_ROOTCN);
	
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
	
	// TODO: react to start_vaddr
	printf("Init foreign %p %p\n", &st->vnode_meta_alloc, &st->page_meta_alloc);
	st->slot_alloc = ca;

	//st->vnode_meta_alloc = current.vnode_meta_alloc;
	//st->page_meta_alloc = current.page_meta_alloc;
	
	//initialize and grow the slab allocators for struct mm_entry_meta and struct mm_vnode_meta
	slab_init(&(st->vnode_meta_alloc), sizeof(struct mm_vnode_meta), slab_default_refill);
	slab_default_refill(&(st->vnode_meta_alloc));
	//slab_grow(&(st->vnode_meta_alloc), slab_vnode_init_buf, SLAB_INIT_BUF_LEN);
	
	slab_init(&(st->page_meta_alloc), sizeof(struct mm_entry_meta), slab_default_refill);
	//slab_grow(&(st->page_meta_alloc), slab_page_init_buf, SLAB_INIT_BUF_LEN);
	slab_default_refill(&(st->page_meta_alloc));
	
	// XXX: temporary fix, but occupy the first L0 slot since mappings in there tend to be taken already
	
	assert(get_croot_addr(pdir) == CPTR_ROOTCN);
	
	// populate the root vnode
	st->root.cap = pdir;
	st->root.first = NULL;
	st->root.this.map = NULL_CAP;
	st->root.this.next = NULL;
	st->root.this.slot = -1;
	st->root.used = 1;
	st->offset = 1UL << 39;
	
	assert(get_croot_addr(st->root.cap) == CPTR_ROOTCN);
	
    return SYS_ERR_OK;
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
	
	errval_t err = paging_init_state(&current, VMSAv8_64_L1_BLOCK_SIZE, cap_vroot, get_default_slot_allocator());
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "failed to init paging state\n");
		return err_push(err, LIB_ERR_PMAP_INIT);
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
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong otherwise.
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
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags)
{
    // TODO(M2):
    // - Find and allocate free region of virtual address space of at least bytes in size.
    // - Map the user provided frame at the free virtual address
    // - return the virtual address in the buf parameter
    //
    // Hint:
    //  - think about what mapping configurations are actually possible

	errval_t err;
	
	// refill the slab allocators if necessary
	// err = refill_slab_alloc(&slab_page_refilling, &(st->page_meta_alloc));
	// if (err_is_fail(err)) {
	// 	DEBUG_ERR(err, "refilling the page meta slab allocator failed");
	// }
	// err = refill_slab_alloc(&slab_vnode_refilling, &(st->vnode_meta_alloc));
	// if (err_is_fail(err)) {
	// 	DEBUG_ERR(err, "refilling the vnode meta slab allocator failed");
	// }

	int slab_pages_required = (bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE + SLAB_REFILL_THRESHOLD;
	int slab_vnodes_required = slab_pages_required + 5;
	printf("MAP REQUIRES PAGES %d/%d, VNODES %d/%d\n", slab_pages_required, slab_freecount(&st->page_meta_alloc), slab_vnodes_required, slab_freecount(&st->vnode_meta_alloc));
	while (slab_freecount(&st->page_meta_alloc) < slab_pages_required || slab_freecount(&st->vnode_meta_alloc) < slab_vnodes_required) {
		if (slab_freecount(&st->page_meta_alloc) < slab_pages_required) st->page_meta_alloc.refill_func(&(st->page_meta_alloc));
		if (slab_freecount(&st->vnode_meta_alloc) < slab_vnodes_required) st->vnode_meta_alloc.refill_func(&(st->vnode_meta_alloc));
	} 
	printf("ACQUIRED PAGES %d, VNODES %d\n", slab_freecount(&st->page_meta_alloc), slab_freecount(&st->vnode_meta_alloc));
	
	// for testing only now, should be error handled and stuff
	//err = rec_map(st, &(st->root), bytes, frame, buf, 0, 0, flags, 0);
	*buf = (void*)st->offset;
	st->offset += 1UL << 32;
	err = rec_map_fixed(st, &(st->root), (lvaddr_t)*buf, bytes, frame, 0, flags, 0);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "allocation of virtual addresses failed");
		return LIB_ERR_PMAP_NOT_MAPPED;
	}
	printf("DONE\n");
	
	return SYS_ERR_OK;
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
    /*
     * TODO(M1):
     *    - Map a frame assuming all mappings will fit into one leaf page table (L3)
     * TODO(M2):
     *    - General case: you will need to handle mappings spanning multiple leaf page tables.
     *    - Make sure to update your paging state to reflect the newly mapped region
     *
     * Hint:
     *  - think about what mapping configurations are actually possible
     */
	
	int slab_pages_required = (bytes + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE + SLAB_REFILL_THRESHOLD;
	int slab_vnodes_required = slab_pages_required + 5;
	printf("RMAP REQUIRES PAGES %d, VNODES %d\n", slab_pages_required, slab_vnodes_required);
	while (slab_freecount(&st->page_meta_alloc) < slab_pages_required || slab_freecount(&st->vnode_meta_alloc) < slab_vnodes_required) {
		if (slab_freecount(&st->page_meta_alloc) < slab_pages_required) st->page_meta_alloc.refill_func(&(st->page_meta_alloc));
		if (slab_freecount(&st->vnode_meta_alloc) < slab_vnodes_required) st->vnode_meta_alloc.refill_func(&(st->vnode_meta_alloc));
	} 
	printf("RACQUIRED PAGES %d, VNODES %d\n", slab_freecount(&st->page_meta_alloc), slab_freecount(&st->vnode_meta_alloc));

	errval_t err;
	
	// refill the slab allocators if necessary
	err = refill_slab_alloc(&slab_page_refilling, &(st->page_meta_alloc));
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "refilling the page meta slab allocator failed");
	}
	err = refill_slab_alloc(&slab_vnode_refilling, &(st->vnode_meta_alloc));
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "refilling the vnode meta slab allocator failed");
	}
		
	//debug_printf("Default Slot Alloc Space: %d, NSlots: %d\n", get_default_slot_allocator()->space, get_default_slot_allocator()->nslots);
		
	// map the necessary pages using the recursive helper function
	err = rec_map_fixed(st, &st->root, vaddr, bytes, frame, 0, flags, 0); 
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "mapping of fixed address failed");
		return LIB_ERR_PMAP_NOT_MAPPED;
	}
	printf("RDONE\n");

	//while (bytes == 17084416);
	
    return SYS_ERR_OK;
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
