/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
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

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>
#include <mdb/types.h>

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst)
{
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc = slot_alloc_func;
    mm->objtype = objtype;

    mm->pending_root = NULL;

    slab_init(&mm->slabs, sizeof(struct mm_node), slab_refill_func);
    for (int i = 0; i < MM_NODE_TABLE_SIZE; i++) mm->node_table[i] = NULL;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

inline unsigned char __address_alignment2_bits(genpaddr_t address) {    
    return __builtin_ctzl(address);
}

inline unsigned char __floor_block_size2_bits(gensize_t block_size) {
    assert(block_size > 0);
    return (MM_ADDR_BITS - 1 - __builtin_clzl(block_size));
}

inline unsigned char __ceil_block_size2_bits(gensize_t block_size) {
    assert(block_size > 1);
    return (MM_ADDR_BITS - __builtin_clzl(block_size - 1));
}

inline gensize_t __bits_to_gensize(unsigned char bits) {
    assert(bits < MM_ADDR_BITS);
    return ((gensize_t) 1) << bits;
}

// No intrinsic available :/
static inline capaddr_t __mm__capref_to_key(struct capref cap) {
    capaddr_t key = get_cap_addr(cap);
    
    key = (key & 0xFFFF0000U) >> 16 | (key & 0x0000FFFFU) << 16;
    key = (key & 0xFF00FF00U) >> 8 | (key & 0x00FF00FFU) << 8;
    key = (key & 0xF0F0F0F0U) >> 4 | (key & 0x0F0F0F0FU) << 4;
    key = (key & 0xCCCCCCCCU) >> 2 | (key & 0x33333333U) << 2;
    key = (key & 0xAAAAAAAAU) >> 1 | (key & 0x55555555U) << 1;
    
    return key;
}

inline bool __mm_pseudo_random_bit(capaddr_t key) {
    return key & MM_PENDING_TREE_PIVOT;
}

inline struct mm_block __mm_create_block(struct capref root_cap, gensize_t root_offset, unsigned char size_bits, unsigned char alignment_bits) {
    struct mm_block block;

    block.root_cap = root_cap;
    block.root_offset = root_offset;
    block.size_bits = size_bits;
    block.alignment_bits = alignment_bits;

    return block;
}

static inline errval_t __mm_create_node(struct mm *mm, struct mm_node **node, struct mm_block block, struct mm_node *parent) {
    static bool is_refilling = false;

    if (!is_refilling && slab_freecount(&mm->slabs) <= (MM_ADDR_BITS - BASE_PAGE_BITS - 1) * 2) { // at most 2 slabs are needed for each of the layers to reach a BASE_PAGE_SIZE leaf
        is_refilling = true;
        struct capref ram, frame, some;
        errval_t     err = mm->slot_alloc(mm->slot_alloc_inst, 1, &frame);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to alloc capabilities\n");
            return err_push(err, MM_ERR_SLOT_NOSLOTS);
        }

           err = mm->slot_alloc(mm->slot_alloc_inst, 1, &some);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to alloc capabilities\n");
            return err_push(err, MM_ERR_SLOT_NOSLOTS);
        }

        mm_alloc(mm, 4096, &ram);
        // Hint: you can't just use malloc here...
        // Hint: For M1, just use the fixed mapping funcionality, however you may want to replace
        //       the fixed mapping later to avoid conflicts.
        err = cap_retype(frame, ram, 0, ObjType_Frame, 4096, 1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to snip part of capability\n");
            return err_push(err, MM_ERR_CHUNK_NODE);
        }
        paging_map_fixed_attr(get_current_paging_state(), 0x0000090000000000+mm->slabs.offset, frame, 4096, 0, some);


        printf("%ld\n", 0x0000090000000000+mm->slabs.offset);
        printf("%i\n", *(int*)(0x0000090000000000+mm->slabs.offset));

        slab_grow(&mm->slabs, (void *)( 0x0000090000000000+mm->slabs.offset), 4096);
        mm->slabs.offset+=4096;


        printf("got some slabs\n");
        is_refilling = false;
        // TODO alloc additional slabs :)
    }

    *node = slab_alloc(&mm->slabs);
    if (*node == NULL) return MM_ERR_SLOT_NOSLOTS;

    (*node)->left = NULL;
    (*node)->right = NULL;
    (*node)->parent = NULL;
    (*node)->is_pending = false;
    (*node)->is_leaf = true;
    (*node)->key = 0;

    (*node)->parent = parent;
    (*node)->block = block;

    return SYS_ERR_OK;
}

inline void __mm_add_node_list(struct mm *mm, struct mm_node *node) {
    const int index = MM_NODE_TABLE_INDEX(node->block.size_bits, node->block.alignment_bits);

    assert(node->left == NULL);
    assert(node->right == NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    if (mm->node_table[index] != NULL) mm->node_table[index]->left = node;
    node->right = mm->node_table[index];
    mm->node_table[index] = node;
}

inline void __mm_remove_node_list(struct mm *mm, struct mm_node *node) {
    const int index = MM_NODE_TABLE_INDEX(node->block.size_bits, node->block.alignment_bits);

    assert(node != NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    if (node->right != NULL) {
        node->right->left = node->left;
    }

    if (node->left != NULL) {
        node->left->right = node->right;
    } else {
        assert(mm->node_table[index] == node);
        mm->node_table[index] = node->right;
    }

    node->left = NULL;
    node->right = NULL;
}


static inline void __mm__add_node_tree(struct mm *mm, struct mm_node *node, struct capref cap) {
    assert(node->left == NULL);
    assert(node->right == NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    node->is_pending = true;
    node->key = __mm__capref_to_key(cap);

    struct mm_node **slot = &mm->pending_root;
    while (*slot != NULL) {
        assert(node->key != (*slot)->key);
        if (node->key < (*slot)->key) slot = &((*slot)->left);
        else slot = &((*slot)->right);
    }

    *slot = node;
}

static inline struct mm_node* __mm__remove_node_tree(struct mm *mm, struct capref cap) {
    capaddr_t key = __mm__capref_to_key(cap);

    struct mm_node *parent = NULL;
    struct mm_node **node_p = &mm->pending_root;
    while (key != (*node_p)->key) {
        parent = *node_p;
        if (key < parent->key) node_p = &parent->left;
        else node_p = &parent->right;
        assert(*node_p != NULL);
    }
    struct mm_node *node = *node_p, *predecessor, *predecessor_parent = NULL;
    if (__mm_pseudo_random_bit(key)) {
        predecessor = node->left;        
        if (predecessor == NULL) *node_p = node->right;
        else {
            while (predecessor->right != NULL) {
                predecessor_parent = predecessor;
                predecessor = predecessor->right;
            }
            if (predecessor_parent != NULL) {
                predecessor_parent->right = predecessor->left;
                predecessor->left = node->left;
            }
            
            predecessor->right = node->right;
            *node_p = predecessor;
        }
    } else {
        predecessor = node->right;
        if (predecessor == NULL) *node_p = node->left;
        else {
            while (predecessor->left != NULL) {
                predecessor_parent = predecessor;
                predecessor = predecessor->left;
            }
            if (predecessor_parent != NULL) {
                predecessor_parent->left = predecessor->right;
                predecessor->right = node->right;
            }
            
            predecessor->left = node->left;            
            *node_p = predecessor;
        }
    }
    assert(node->is_pending == true);
    assert(node->is_leaf == true);
    assert(node->key == key);

    node->left = NULL;
    node->right = NULL;
    node->is_pending = false;
    node->key = 0;

    return node;
}

static inline errval_t __mm_add_aligned(struct mm *mm, struct mm_block block, struct mm_node *parent, struct mm_node **node_p) {
    assert(node_p == NULL || *node_p == NULL);

    struct mm_node *node;
    errval_t err = __mm_create_node(mm, &node, block, parent);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to allocate node\n");
        return err_push(err, MM_ERR_SLOT_NOSLOTS);
    }

    if (node_p != NULL) *node_p = node;

    __mm_add_node_list(mm, node);

    return SYS_ERR_OK;
}

errval_t mm_add(struct mm *mm, struct capref cap)
{
    struct capability c;
    errval_t err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get the frame info\n");
        return err_push(err, MM_ERR_FIND_NODE);
    }
    assert(c.type == ObjType_RAM);
    
    genpaddr_t base = c.u.ram.base;
    gensize_t offset = 0, bytes = c.u.ram.bytes;

    while (offset < bytes) {
        unsigned char alignment_bits = __address_alignment2_bits(base + offset);
        unsigned char block_size_bits = MIN(__floor_block_size2_bits(bytes - offset), alignment_bits);
        gensize_t block_size = __bits_to_gensize(block_size_bits);

        struct mm_block block = __mm_create_block(cap, offset, block_size_bits, alignment_bits);
        err = __mm_add_aligned(mm, block, NULL, NULL);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to add capabilities\n");
            return err_push(err, MM_ERR_MM_ADD);
        }

        offset += block_size;
    }

    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    errval_t err;
    size = MAX(size, BASE_PAGE_SIZE);
    alignment = MAX(alignment, BASE_PAGE_SIZE);

    unsigned char block_size_bits = __ceil_block_size2_bits(size), alignment_bits = __address_alignment2_bits(alignment);
    if (__bits_to_gensize(alignment_bits) != alignment) {
        return MM_ERR_UNSUPPORTED_ALIGNMENT;
    }
    alignment_bits = MAX(block_size_bits, alignment_bits);

    unsigned char search_block_size_bits = block_size_bits, search_alignment_bits;
    assert(block_size_bits < MM_ADDR_BITS);
    while (search_block_size_bits < MM_ADDR_BITS) {
        search_alignment_bits = MAX(search_block_size_bits, alignment_bits);

        while (search_alignment_bits < MM_ADDR_BITS && mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)] == NULL) search_alignment_bits++;
        if (search_alignment_bits < MM_ADDR_BITS) break;

        search_block_size_bits++;
    }
    if (search_block_size_bits == MM_ADDR_BITS) {
        DEBUG_ERR(MM_ERR_NOT_FOUND, "no satisfactory memory available\n");
        return MM_ERR_NOT_FOUND;
    }

    gensize_t search_block_size = __bits_to_gensize(search_block_size_bits);
    struct mm_node *node = mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)];
    assert(node != NULL);

    while (search_block_size_bits > block_size_bits) {
        struct mm_block block = node->block;

        __mm_remove_node_list(mm, node);


        struct mm_block child0 = __mm_create_block(block.root_cap, block.root_offset, search_block_size_bits - 1, search_alignment_bits); 
        err = __mm_add_aligned(mm, child0, node, &node->left);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to add capabilities\n");
            return err_push(err, MM_ERR_MM_ADD);
        }
        assert(node->left != NULL);

        struct mm_block child1 = __mm_create_block(block.root_cap, block.root_offset + search_block_size / 2, search_block_size_bits - 1, search_alignment_bits - 1); 
        err = __mm_add_aligned(mm, child1, node, &node->right);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to add capabilities\n");
            return err_push(err, MM_ERR_MM_ADD);
        }       
        assert(node->right != NULL);
        
        search_block_size /= 2;
        search_block_size_bits--;
        if (search_alignment_bits > alignment_bits) search_alignment_bits--;

        assert(node->is_leaf);
        node->is_leaf = false;
        node = mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)];
        assert(node != NULL);
    }

    assert(node->block.size_bits == search_block_size_bits);
    assert(node->block.alignment_bits == search_alignment_bits);
    assert(search_block_size_bits == block_size_bits);
    assert(search_alignment_bits >= alignment_bits);

    // Remove the node from the list before allocating the capability as another block could be requested during the call (for more capabilities) and we do not want the same block to be found again!
    __mm_remove_node_list(mm, node);

    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to alloc capabilities\n");
        return err_push(err, MM_ERR_SLOT_NOSLOTS);
    }
    
    err = cap_retype(*retcap, node->block.root_cap, node->block.root_offset, ObjType_RAM, search_block_size, 1);
    if (err_is_fail(err)) {
        printf("%i\n", search_block_size);
        DEBUG_ERR(err, "failed to snip part of capability\n");
        return err_push(err, MM_ERR_CHUNK_NODE);
    }

    __mm__add_node_tree(mm, node, *retcap);

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, 0, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err = cap_destroy(cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to snip part of capability2\n");
        return err_push(err, MM_ERR_CHUNK_NODE);
    }

    struct mm_node *node = __mm__remove_node_tree(mm, cap);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    
    struct mm_node *parent = node->parent;

    while (parent != NULL) {
        if (parent->left == node) {
            if (parent->right->is_pending || !parent->right->is_leaf) break;
            else __mm_remove_node_list(mm, parent->right);
        } else {
            assert(parent->right == node);
            if (parent->left->is_pending || !parent->left->is_leaf) break;
            else __mm_remove_node_list(mm, parent->left);
        }

        slab_free(&mm->slabs, parent->left);
        slab_free(&mm->slabs, parent->right);
        parent->left = NULL;
        parent->right = NULL;
        assert(parent->is_leaf == false);
        parent->is_leaf = true;

        node = parent;
        parent = node->parent;
    }

    __mm_add_node_list(mm, node);

    return SYS_ERR_OK;
}
