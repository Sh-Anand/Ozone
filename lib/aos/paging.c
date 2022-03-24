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

#define SLAB_REFILL_THRESHOLD 64
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

/**
 * @brief Recursively maps a frame at a fixed address. It is assumed that no slab refill will try to allocate memory inside the range to be allocated.
 * 
 * @param st the paging state
 * @param root the root of the table which the memory should be mapped into
 * @param rvaddr the address to start mapping at relative to the beginning of the table
 * @param size the size of the mapping to perform in bytes
 * @param frame the frame to map
 * @param frame_offset the offset of the beginning of the mapping into the provided frame
 * @param flags the maps to use for the mapping
 * @param depth the depth of the recursive call
 * @return errval_t 
 */
static errval_t rec_map_fixed(struct paging_state *st, struct mm_vnode_meta *root, lvaddr_t rvaddr, size_t size, struct capref frame, size_t frame_offset, uint64_t flags, int depth, lvaddr_t abs_addr, uint64_t slots) {
	
	assert(rvaddr % BASE_PAGE_SIZE == 0);
	assert(size % BASE_PAGE_SIZE == 0);
	assert(size > 0);

	errval_t err;
	size_t bit_offset = 39 - 9 * depth;
	size_t sub_region_size = 1UL << bit_offset;
	capaddr_t start = rvaddr >> bit_offset;
	capaddr_t end = (rvaddr + size - 1) >> bit_offset;	
	assert(start < 512 && end < 512);
	printf("%ld, %ld, %ld, %ld, %d\n", rvaddr, size, frame_offset, sub_region_size, depth);
	printf("%i, %i\n", start, end);

	union mm_meta **pointer_to_current_meta = &(root->first); // this tracks the address of the pointer we need to write
	union mm_meta *current_meta = root->first; // this tracks the current_meta page table entry while walking through the list
	
	for (int i = start; i <= end; i++) {
		// walk through the list until current_meta is either the required entry, or the first entry after the point of insertion
		while (current_meta != NULL && current_meta->entry.slot < i) {
			pointer_to_current_meta = &(current_meta->entry.next);
			current_meta = current_meta->entry.next;
		}
		
		// check if we need to create a new entry
		if (current_meta == NULL || current_meta->entry.slot != i) {
			// declare necessary variables
			union mm_meta *new_entry; //
			struct capref mapee;
			size_t off;
			
			if (depth < 3) {
				// this is another vnode to create
				refill_slab_alloc(&slab_vnode_refilling, &(st->vnode_meta_alloc));
				new_entry = slab_alloc(&(st->vnode_meta_alloc)); // allocate space for another struct mm_vnode_meta
				new_entry->vnode.first = NULL;
				err = pt_alloc(st, vnode_types[depth], &(new_entry->vnode.cap));
				if (err_is_fail(err)) {
					DEBUG_ERR(err, "pt_alloc failed");
					return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
				}
				mapee = new_entry->vnode.cap; // a new vnode has to be mapped
				off = 0; // there is no offset for vnodes
			} else {
				// this is a page entry to create
				refill_slab_alloc(&slab_page_refilling, &(st->page_meta_alloc));
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
			//debug_printf("i: %d, current_meta %p, current->slot: %d\n", i, current_meta, current_meta->entry.slot);
			if (depth >= 3) debug_printf("USEFUL INFORMATION: size: %d, Depth %d trying to map address: %020p slots: %016ld capaddr current: %p\n", size, depth, abs_addr, slots*10000 + i, get_cap_addr(current_meta->entry.map));
			assert(depth < 3);
		}
				
		if (depth < 3) {
			// this is not the last level page table, so continue with the next layer
			lvaddr_t i_start = MAX(rvaddr, i * sub_region_size); // start of the subregion to allocate
			lvaddr_t i_end = MIN(rvaddr + size, (i + 1) * sub_region_size); // end of the subregion to allocate

			err = rec_map_fixed(st, &current_meta->vnode, i_start % sub_region_size, i_end - i_start, frame, frame_offset + i_start - rvaddr, flags, depth + 1, abs_addr, slots*10000 + i);
			if (err_is_fail(err)) {
				// TODO: verify no cleanup needed
				DEBUG_ERR(err, "failed to map fixed address");
				return err_push(err, LIB_ERR_PMAP_NOT_MAPPED);
			}
		} else {
			//printf("\x1b[1;31;47m USEFUL INFORMATION: successfully mapped address %016p slot %016ld capaddr current: %p\x1b[0m\n", abs_addr, slots*10000 + i, get_cap_addr(current_meta->entry.map));
		}
	}
	
	
	return SYS_ERR_OK;
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
	slot0->entry.next = NULL;
	slot0->vnode.first = NULL;
	
	assert(get_croot_addr(pdir) == CPTR_ROOTCN);
	
	// populate the root vnode
	st->root.cap = pdir;
	st->root.first = slot0;
	st->root.this.map = NULL_CAP;
	st->root.this.next = NULL;
	st->root.this.slot = -1;
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
    st->offset = (st->offset + alignment - 1) / alignment * alignment;	
    *buf = (void*)st->offset;
	st->offset += bytes;

    return SYS_ERR_OK;
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

	
	paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
	err = paging_map_fixed_attr(st, (lvaddr_t)*buf, frame, bytes, flags);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "allocation of virtual addresses failed");
		return LIB_ERR_PMAP_NOT_MAPPED;
	}	
	
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

	printf("%p: gave %p\n", st, vaddr);

	errval_t err;
		
	// map the necessary pages using the recursive helper function
	err = rec_map_fixed(st, &st->root, vaddr, bytes, frame, 0, flags, 0, vaddr, 0); 
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "mapping of fixed address failed");
		return LIB_ERR_PMAP_NOT_MAPPED;
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
