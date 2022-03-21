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

#define SLAB_INIT_BUF_LEN 262144 // for starting out, 256kB should be enough for the memory manager to begin mapping some pages
static char slab_init_buf[SLAB_INIT_BUF_LEN];

const static enum objtype vnode_types[3] = { ObjType_VNode_AARCH64_l1, ObjType_VNode_AARCH64_l2, ObjType_VNode_AARCH64_l3 };

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

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state * st, struct capref *ret) 
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


static errval_t rec_map(struct paging_state *st, struct mm_vnode_meta *root, lvaddr_t rvaddr, size_t size, struct capref frame, size_t frame_offset, uint64_t flags, int depth) {
	// declare and define necessary variables
	errval_t err;
	capaddr_t start, end;
	size_t bit_offset = 39 - 9*depth;
	size_t sub_region_size = 1 << bit_offset;
	start = rvaddr >> (39 - depth*9);
	end = (rvaddr + size - 1) >> (39 - depth*9);
	
	union mm_meta **pointer_to_current = &(root->first); // this tracks the address of the pointer we need to write
	union mm_meta *current = root->first; // this tracks the current page table entry while walking through the list
	
	for (int i = start; i <= end; i++) {
		// walk through the list until current is either the required entry, or the first entry after the point of insertion
		while (current != NULL && current->entry.slot < i) {
			pointer_to_current = &(current->entry.next);
			current = current->entry.next;
		}
		
		// check if we found the necessary entry
		if (current != NULL && current->entry.slot == i) {
			// found the necessary root
		} else {
			// create new entry
			union mm_meta *new_entry = slab_alloc(&(st->slab_alloc)); // this always allocates space for a full vnode struct instead of only an entry for pages
			
			new_entry->entry.slot = i; // set the slot of the new element
			new_entry->entry.next = current; // set the next pointer of the new element
			*pointer_to_current = new_entry; // link the new element into the list
			
			// TODO: react to the depth of the current iteration
			
			err = pt_alloc(st, vnode_types[depth], &(new_entry->vnode.cap));
			if (err_is_fail(err)) {
				DEBUG_ERR(err, "pt_alloc failed");
				return LIB_ERR_PMAP_NOT_MAPPED;
			}
			
			// allocate the mapping capability
			err = st->slot_alloc->alloc(st->slot_alloc, &(new_entry->entry.map));
			if (err_is_fail(err)) {
				DEBUG_ERR(err, "slot_alloc failed");
				st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
				return LIB_ERR_PMAP_NOT_MAPPED;
			}
			
			// map the page
			err = vnode_map(root->cap, new_entry->vnode.cap, i, flags, 0 /* for now this is always 0 */, 1 /* for now we only map one page at a time in all cases */, new_entry->entry.map);
			if (err_is_fail(err)) {
				DEBUG_ERR(err, "vnode_map failed");
				st->slot_alloc->free(st->slot_alloc, new_entry->entry.map);
				st->slot_alloc->free(st->slot_alloc, new_entry->vnode.cap);
				return LIB_ERR_PMAP_NOT_MAPPED;
			}
			
			// update current to be used later
			current = new_entry;
		}
		
		lvaddr_t new_rvaddr = rvaddr - i*sub_region_size;
		
		if (depth < 3) {
			// this is not the last level page table, so continue with the next layer
			rec_map(st, current, new_rvaddr, MIN(sub_region_size, size - i*sub_region_size), frame, flags, frame_offset + i*sub_region_size, depth + 1);
		}
	}
}

/**
 * @brief Tries to find an entry reference, either in the form of a child vnode, or a child page in the case of an L3 root.
 *
 * @param root Non NULL
 * @param slot
 * @return union mm_meta*
 */
static union mm_meta * find_or_insert_entry(struct paging_state *st, struct mm_vnode_meta *root, enum objtype type, int slot, uint64_t flags, struct capref *frame) {
	// sanity checks
	assert(root != NULL);
	assert((type == ObjType_Frame) != (frame == NULL));
	
	union mm_meta *current = root->first;
	union mm_meta **previous = &root->first;
	
	// walk through the list of entries until we find the correct slot, or know we have to insert one
	while (current !=  NULL && current->entry.slot < slot) { 
		previous = &current->entry.next;
		current = current->entry.next;
	}
	
	if (current != NULL && current->entry.slot == slot) {
		return current;
	} else {
		// Create new page table and map it. Use it to create new vnode (pointer)
		
		union mm_meta *meta = slab_alloc(&(st->slab_alloc));	
		st->slot_alloc->alloc(st->slot_alloc, &(meta->entry.map));
		if (type == ObjType_Frame) {
			
		} else {
			errval_t err = pt_alloc(st, type, &(meta->vnode.cap));
			// error handling
			
			err = vnode_map(root->cap, meta->vnode.cap, slot, flags, 0, 1, meta->entry.map);
			
			if (current != NULL) meta->entry.next = current;
			
			*previous = meta;
		}
	}
	
	return NULL;
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
    return LIB_ERR_NOT_IMPLEMENTED;
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
    return LIB_ERR_NOT_IMPLEMENTED;
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
	
	//errval_t err;
	//err = slot_alloc_init();
	//DEBUG_ERR(err, "slot_alloc_init");
	
	//err = two_level_slot_alloc_init(&msa);
	//if (err_is_fail(err)) {
	//	USER_PANIC_ERR(err, "Failed to init slot_alloc");
	//	return err;
	//}
	//current.slot_alloc = &(msa.a);
	
	current.slot_alloc = get_default_slot_allocator();
	
	current.root_page_tbl.cap = cap_vroot;
	current.root_page_tbl.first = NULL;
	current.root_page_tbl.last = NULL;
	
	
	slab_init(&(current.slab_alloc), sizeof(union mm_meta), slab_default_refill);
	slab_grow(&(current.slab_alloc), slab_init_buf, SLAB_INIT_BUF_LEN);
	
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

    return LIB_ERR_NOT_IMPLEMENTED;
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
	
	static int slab_refilling = 0;
	if (!slab_refilling && slab_freecount(&(st->slab_alloc)) < 64) {
		slab_refilling = 1;
		debug_printf("Refilling Paging slabs...");
		errval_t e = slab_default_refill(&(st->slab_alloc));
		debug_printf("Slab Refilling error: %d\n", err_no(e));
		slab_refilling = 1;
	}
	
	// calculate the slots necessary for this mapping
	capaddr_t slot[4];
	slot[0] = (0x0000ff8000000000 & vaddr) >> 39;
	slot[1] = (0x0000007fc0000000 & vaddr) >> 30;
	slot[2] = (0x000000003fe00000 & vaddr) >> 21;
	slot[3] = (0x00000000001ff000 & vaddr) >> 12;
	
	//debug_printf("Default Slot Alloc Space: %d, NSlots: %d\n", get_default_slot_allocator()->space, get_default_slot_allocator()->nslots);
	
	struct capref l1_cap, l2_cap, l3_cap;
	
	errval_t err;
	
	union mm_meta *root = &(st->root);
	
	for (int i = 0; i < 4; i++) {
		union mm_meta *current = root->first;
		union mm_meta **previous = &root->first;
		
		// walk through the list of entries until we find the correct slot, or know we have to insert one
		while (current !=  NULL && current->entry.slot < slot[i]) { 
			previous = &current->entry.next;
			current = current->entry.next;
		}
		
		if (current != NULL && current->entry.slot == slot[i]) {
			return current;
		} else {
			// Create new page table and map it. Use it to create new vnode (pointer)
			
			union mm_meta *meta = slab_alloc(&(st->slab_alloc));	
			st->slot_alloc->alloc(st->slot_alloc, &(meta->entry.map));
			
			if (i < 3) {
				errval_t err;
				err = pt_alloc(st, vnode_types[i], &(meta->vnode.cap));
				// error handling
				
				err = vnode_map(root->vnode.cap, meta->vnode.cap, slot[i], flags, 0, 1, meta->entry.map);
				// error handling
				
				if (current != NULL) meta->entry.next = current;
				
				*previous = meta;
			} else {
				assert(i == 3);
			}
		}
	}
	
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
