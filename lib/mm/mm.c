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

/**
 * @brief Initialize the instance of mm
 * 
 * @param mm The mm to initialize
 * @param objtype Should be ObjType_RAM
 * @param slab_refill_func A function to refill slabs
 * @param slot_alloc_func A function to alloc slots
 * @param slot_refill_func A function to refill slots
 * @param slot_alloc_inst A instance of a slot allocator
 * @return errval_t 
 */
errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst)
{
    assert(objtype == ObjType_RAM);

    mm->slot_alloc_inst = slot_alloc_inst;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc = slot_alloc_func;
    mm->objtype = objtype;

    mm->pending_root = NULL;

    slab_init(&mm->slabs, sizeof(struct mm_node), slab_refill_func);
    for (int i = 0; i < MM_NODE_TABLE_SIZE; i++) mm->node_table[i] = NULL; // Setup linked-list table

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

/**
 * @brief Return the alignment bits of the passed address
 * 
 * @param address Some address to calculate the alignment of
 * @return Bit equivalent of the alignemnt of the address
 */
static unsigned char __address_alignment2_bits(genpaddr_t address) {
    if (address == 0) return MM_ADDR_BITS - 1;
    return __builtin_ctzl(address);
}

/**
 * @brief Returns the floored block_size
 * 
 * @param block_size The size to convert
 * @return The bit size that is enough if the size is a power of 2 but less otherwise
 */
static unsigned char __floor_block_size2_bits(gensize_t block_size) {
    if (block_size == 0) return 0;
    return (MM_ADDR_BITS - 1 - __builtin_clzl(block_size));
}

/**
 * @brief Returns the ceiled block_size
 * 
 * @param block_size The size to convert
 * @return The bit size that is as least as large as the passed size
 */
static unsigned char __ceil_block_size2_bits(gensize_t block_size) {
    if (block_size <= 1) return 0;
    else return (MM_ADDR_BITS - __builtin_clzl(block_size - 1));
}

// 
/**
 * @brief Convert a bit size to a normal size
 * 
 * @param bits The bit size
 * @return gensize_t The normal size equivalent
 */
static gensize_t __bits_to_gensize(unsigned char bits) {
    assert(bits < MM_ADDR_BITS);
    return ((gensize_t) 1) << bits;
}

/**
 * @brief Return the key to use in the pending tree
 * 
 * @param cap The capability to calculate the key of
 * @return capaddr_t Reversed capability addr (tree should balance nicely then)
 */
static capaddr_t __mm_capref_to_key(struct capref cap) {
    capaddr_t key = get_cap_addr(cap);
    
    // There is no intrinsic available :/
    key = (key & 0xFFFF0000U) >> 16 | (key & 0x0000FFFFU) << 16;
    key = (key & 0xFF00FF00U) >> 8 | (key & 0x00FF00FFU) << 8;
    key = (key & 0xF0F0F0F0U) >> 4 | (key & 0x0F0F0F0FU) << 4;
    key = (key & 0xCCCCCCCCU) >> 2 | (key & 0x33333333U) << 2;
    key = (key & 0xAAAAAAAAU) >> 1 | (key & 0x55555555U) << 1;
    
    return key;
}

/**
 * @brief Calculates a pseudo random bit for the given key
 * 
 * When we decide whether to replace a node that should be removed by its predecessor or successor use this pseudo random bit to maintain balance better.
 * 
 * @param key The key to calculate the bit of
 * @return A pseudo-random bit
 */
static bool __mm_pseudo_random_bit(capaddr_t key) {
    return __builtin_parity(key);
}

/**
 * @brief Create a new node
 * 
 * @param mm The instance of mm to use
 * @param node Where to store the result
 * @param root_cap The RAM capability the block is a part of (was originally added to the mm)
 * @param root_offset The offset into the root_cap
 * @param size_bits Size stored as bits. size = 2 ^ size_bits. At most MM_ADDR_BITS - 1
 * @param alignment_bits Alignment stored as bits. alignment = 2 ^ alignment_bits. At most MM_ADDR_BITS - 1
 * @param parent The parent node (i.e. we are a result of a split of it) or NULL if we are a root
 * @return errval_t 
 */
static errval_t __mm_create_node(struct mm *mm, struct mm_node **node, struct capref root_cap, gensize_t root_offset, unsigned char size_bits, unsigned char alignment_bits, struct mm_node *parent) {
    assert(size_bits < MM_ADDR_BITS);
    assert(alignment_bits < MM_ADDR_BITS);

    static bool is_refilling = false; // Avoid nested refilling
    errval_t err;

    // Refill if required
    if (!is_refilling && slab_freecount(&mm->slabs) <= MM_SLAB_RESERVE) {
		is_refilling = true;
        err = slab_default_refill(&mm->slabs);
        is_refilling = false;
        if (err_is_fail(err)) return err_push(err, MM_ERR_NODE_REFILL);
    }

    *node = slab_alloc(&mm->slabs);
    if (*node == NULL) return MM_ERR_NODE_ALLOC;

    (*node)->left = NULL;
    (*node)->right = NULL;
    (*node)->parent = NULL;
    (*node)->is_pending = false;
    (*node)->is_leaf = true;
    (*node)->key = 0;

    (*node)->parent = parent;

    (*node)->block.root_cap = root_cap;
    (*node)->block.root_offset = root_offset;
    (*node)->block.size_bits = size_bits;
    (*node)->block.alignment_bits = alignment_bits;

    return SYS_ERR_OK;
}

/**
 * @brief Destroys the given node
 * 
 * @param mm The mm instance
 * @param node The node to free
 */
static void __mm_destroy_node(struct mm *mm, struct mm_node *node) {
    assert(node->left == NULL);
    assert(node->right == NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);
    assert(node->parent != NULL); // Right now a root node should never be deleted! (might change if we implement deinitialization)

    slab_free(&mm->slabs, node);
}

/**
 * @brief Add a node to the free-list
 * 
 * @param mm The mm instance
 * @param node The node to add
 */
static void __mm_add_node_list(struct mm *mm, struct mm_node *node) {
    const int index = MM_NODE_TABLE_INDEX(node->block.size_bits, node->block.alignment_bits);

    // Ensure that we are not currently in either data_structure
    assert(node->left == NULL);
    assert(node->right == NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    // Insert the node into the linked list and update the old first element.
    if (mm->node_table[index] != NULL) mm->node_table[index]->left = node;
    node->right = mm->node_table[index];
    mm->node_table[index] = node;
}

/**
 * @brief Remove a node from the free-list
 * 
 * @param mm The mm instance
 * @param node The node to remove
 */
static void __mm_remove_node_list(struct mm *mm, struct mm_node *node) {
    const int index = MM_NODE_TABLE_INDEX(node->block.size_bits, node->block.alignment_bits);

    // Assert that all fields but left/right are untouched
    assert(node != NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    // Remove the element from the list and update the neighbors (if they exist)

    if (node->right != NULL) {
        node->right->left = node->left;
    }

    if (node->left != NULL) {
        node->left->right = node->right;
    } else { // We are the first node, hence we should be pointed to by the table
        assert(mm->node_table[index] == node);
        mm->node_table[index] = node->right;
    }

    // Reset pointers to indicate that we are not part of any data structure
    node->left = NULL;
    node->right = NULL;
}

/**
 * @brief Collapse the parents of the node, until some child is pending
 * 
 * @param mm The mm instance
 * @param node A pointer to the node to remove (has to removed from the tree but not yet added back to the list)
 */
static void __mm_collapsing_add_node_list(struct mm *mm, struct mm_node *node) {
    assert(node->is_pending == false);
    assert(node->is_leaf == true);

    // As long as our sibling is not pending, merge the blocks together again
    while (node->parent != NULL) {
        assert(node->parent->is_pending == false);
        assert(node->parent->is_leaf == false);
        if (node->parent->left == node) { // We are the left child
            if (node->parent->right->is_pending || !node->parent->right->is_leaf) break;
            else __mm_remove_node_list(mm, node->parent->right);
        } else { // We are the right child
            assert(node->parent->right == node);
            if (node->parent->left->is_pending || !node->parent->left->is_leaf) break;
            else __mm_remove_node_list(mm, node->parent->left);
        }

        __mm_destroy_node(mm, node->parent->left);
        __mm_destroy_node(mm, node->parent->right);
        node->parent->left = NULL;
        node->parent->right = NULL;
        node->parent->is_leaf = true;

        node = node->parent;
    }

    __mm_add_node_list(mm, node);
}

/**
 * @brief Search the slot where the given key should be inserted (or the slot pointing to the key if it already exists)
 * 
 * @param slot The slot to start with
 * @param key The key to search for
 * @return struct mm_node**
 */
static struct mm_node** __mm_search_slot_tree(struct mm_node **slot, capaddr_t key) {
    while (*slot != NULL && key != (*slot)->key) {
        if (key < (*slot)->key) slot = &((*slot)->left);
        else slot = &((*slot)->right);
    }

    return slot;
}

/**
 * @brief Add a node to the pending-tree
 * 
 * @param mm The mm instance
 * @param node The node to add
 * @param cap The capref with which we want to be able to find the node again (i.e. the pending cap)
 */
static void __mm_add_node_tree(struct mm *mm, struct mm_node *node, struct capref cap) {
    // Ensure that we are not currently in either data_structure
    assert(node->left == NULL);
    assert(node->right == NULL);
    assert(node->is_pending == false);
    assert(node->is_leaf == true);
    assert(node->key == 0);

    // Set key and is_pending as we are adding the node to the tree
    node->is_pending = true;
    node->key = __mm_capref_to_key(cap);

    // Search the pending tree until we find a free spot (i.e. a pointer to a pointer to a node)
    struct mm_node **slot = __mm_search_slot_tree(&mm->pending_root, node->key);
    // The current key should not have been inserted before
    assert(*slot == NULL);

    // Add the node to the tree
    *slot = node;
}

/**
 * @brief Remove a node from the pending-tree
 * 
 * @param mm The mm instance
 * @param cap The capref we used while adding the node to the tree
 * @return struct mm_node* The pointer to the removed node (for further use) or NULL if node is not present
 */
static struct mm_node* __mm_remove_node_tree(struct mm *mm, struct capref cap) {
    capaddr_t key = __mm_capref_to_key(cap);

    // Find the slot referencing the node to be removed
    struct mm_node **slot = __mm_search_slot_tree(&mm->pending_root, key);
    if (*slot == NULL) return NULL;

    struct mm_node *node = *slot; // Store a pointer to the node, as we will relink the slot

    struct mm_node *substitute;
    // Replace the node in the tree
    // If either child is NULL, substitute by the other
    if (node->left == NULL) substitute = node->right;
    else if (node->right == NULL) substitute = node->left;
    // Otherwise decide pseudo-randomly whether to substitute by the predecessor or the successor
    else {
        struct mm_node *predecessor_parent = NULL;
        if (__mm_pseudo_random_bit(key)) {
            // Find the predecessor
            substitute = node->left;
            while (substitute->right != NULL) {
                predecessor_parent = substitute;
                substitute = substitute->right;
            }
            // If it has a real parent, make it's left child the parents right one
            if (predecessor_parent != NULL) {
                predecessor_parent->right = substitute->left;
                substitute->left = node->left;
            }
            // The substitute has to take the right child of the parent as it's own
            substitute->right = node->right;
        } else {
            // Find the successor
            substitute = node->right;
            while (substitute->left != NULL) {
                predecessor_parent = substitute;
                substitute = substitute->left;
            }
            // If it has a real parent, make it's right child the parents left one
            if (predecessor_parent != NULL) {
                predecessor_parent->left = substitute->right;
                substitute->right = node->right;
            }
            // The substitute has to take the left child of the parent as it's own
            substitute->left = node->left;
        }
    }
    // Link the substitute instead of the node
    *slot = substitute;
    

    // Assert that node has not been changed since it was added
    assert(node->is_pending == true);
    assert(node->is_leaf == true);
    assert(node->key == key);

    // Remove it from the tree
    node->left = NULL;
    node->right = NULL;
    node->is_pending = false;
    node->key = 0;

    return node;
}

/**
 * @brief Add a RAM capability to mm
 * 
 * @param mm The mm instance
 * @param cap A RAM capability to be added
 * @return errval_t 
 */
errval_t mm_add(struct mm *mm, struct capref cap)
{
    errval_t err;
    // Identify the capability to obtain the physical address and size
    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) return err_push(err, MM_ERR_INVALID_CAP);
    if (c.type != ObjType_RAM) return MM_ERR_INVALID_CAP;
    
    genpaddr_t base = c.u.ram.base;
    gensize_t offset = 0, bytes = c.u.ram.bytes;

    struct mm_node *nodes[MM_SLAB_RESERVE];
    int nodes_cnt = 0;

    // Split the memory region into power-of-2 sized blocks which are at least aligned by their size
    while (offset < bytes) {
        assert(nodes_cnt < MM_SLAB_RESERVE);
        // Calculate size and alignment
        unsigned char alignment_bits = __address_alignment2_bits(base + offset);
        unsigned char block_size_bits = MIN(__floor_block_size2_bits(bytes - offset), alignment_bits);
        gensize_t block_size = __bits_to_gensize(block_size_bits);

        // Create block and add it to mm
        err = __mm_create_node(mm, &nodes[nodes_cnt++], cap, offset, block_size_bits, alignment_bits, NULL);
        if (err_is_fail(err)) {
            for (int i = 0; i < nodes_cnt; i++) __mm_destroy_node(mm, nodes[i]);
            return err_push(err, MM_ERR_NODE_CREATE);
        }

        offset += block_size;
    }

    for (int i = 0; i < nodes_cnt; i++) __mm_add_node_list(mm, nodes[i]);

    return SYS_ERR_OK;
}

/**
 * @brief Allocate a RAM capability that has at least the given size and which's address is a multiple of the alignment
 * 
 * @param mm The mm instance
 * @param size The minimum size of the block
 * @param alignment The minimum alignment or 1 if none is required
 * @param retcap Where to return the allocated RAM capability
 * @return errval_t 
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    errval_t err;
    size = MAX(size, BASE_PAGE_SIZE);
    assert(alignment > 0);

    unsigned char block_size_bits = __ceil_block_size2_bits(size), alignment_bits = __address_alignment2_bits(alignment);
    if (block_size_bits >= MM_ADDR_BITS) return MM_ERR_NO_MEMORY;
    if (alignment_bits >= MM_ADDR_BITS || __bits_to_gensize(alignment_bits) != alignment) return MM_ERR_UNSUPPORTED_ALIGNMENT;
    
    // Alignment will be at least BASE_PAGE_BITS or block_size_bits
    alignment_bits = MAX(MAX(alignment_bits, BASE_PAGE_BITS), block_size_bits);
    alignment = __bits_to_gensize(alignment_bits); // The value is currently not used afterwards, but might be in the future

    unsigned char search_block_size_bits = block_size_bits, search_alignment_bits;
    // Increase the block size until we find a satisfactory memory region
    while (search_block_size_bits < MM_ADDR_BITS) {
        search_alignment_bits = MAX(search_block_size_bits, alignment_bits);

        // Test all alignments for the current size
        while (search_alignment_bits < MM_ADDR_BITS && mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)] == NULL) search_alignment_bits++;
        if (search_alignment_bits < MM_ADDR_BITS) break;

        search_block_size_bits++;
    }
    // Our search did not find any region that satisfies alignment and block size
    if (search_block_size_bits == MM_ADDR_BITS) return MM_ERR_NO_MEMORY;

    gensize_t search_block_size = __bits_to_gensize(search_block_size_bits);
    struct mm_node *node = mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)];

    // Split the node into smaller ones until we reach the target block size
    while (search_block_size_bits > block_size_bits) {
        assert(node != NULL);
        assert(node->is_leaf);

        __mm_remove_node_list(mm, node);
        node->is_leaf = false;

        // Split the node in half
        err = __mm_create_node(mm, &node->left, node->block.root_cap, node->block.root_offset, search_block_size_bits - 1, search_alignment_bits, node);
        if (err_is_fail(err)) {
            // We did not create a child, so just add the node back to the list
            assert(node->left == NULL);
            node->is_leaf = true;
            __mm_collapsing_add_node_list(mm, node);
            return err_push(err, MM_ERR_NODE_CREATE);
        }
        assert(node->left != NULL);
        assert(node->left->is_leaf);

        err = __mm_create_node(mm, &node->right, node->block.root_cap, node->block.root_offset + search_block_size / 2, search_block_size_bits - 1, search_alignment_bits - 1, node);
        if (err_is_fail(err)) {
            assert(node->right == NULL);
            __mm_destroy_node(mm, node->left);
            node->left = NULL;
            node->is_leaf = true;
            __mm_collapsing_add_node_list(mm, node);
            return err_push(err, MM_ERR_NODE_CREATE);
        }
        assert(node->right != NULL);
        assert(node->right->is_leaf);

        __mm_add_node_list(mm, node->left);
        __mm_add_node_list(mm, node->right);
        
        search_block_size /= 2;
        search_block_size_bits--;
        if (search_alignment_bits > alignment_bits) search_alignment_bits--;

        node->is_leaf = false;
        node = mm->node_table[MM_NODE_TABLE_INDEX(search_block_size_bits, search_alignment_bits)];
    }

    // Check that we got a valid node satisfying all constraints
    assert(node != NULL);
    assert(node->is_leaf);
    assert(node->block.size_bits == search_block_size_bits);
    assert(node->block.alignment_bits == search_alignment_bits);
    assert(search_block_size_bits == block_size_bits);
    assert(search_alignment_bits >= alignment_bits);

    // Remove the node from the list before allocating the capability as another block could be requested during the call (for more capabilities) and we do not want the same block to be found again!
    __mm_remove_node_list(mm, node);

    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (err_is_fail(err)) return err_push(err, MM_ERR_SLOT_EMPTY);
    
    err = cap_retype(*retcap, node->block.root_cap, node->block.root_offset, ObjType_RAM, search_block_size, 1);
    if (err_is_fail(err)) return err_push(err, MM_ERR_CANNOT_SPLIT_CAP);

    // Add the node to the pending tree
    __mm_add_node_tree(mm, node, *retcap);

    return SYS_ERR_OK;
}

/**
 * @brief Allocate a RAM capability that has at least the given size
 * 
 * @param mm The mm instance
 * @param size The minimum size of the block
 * @param retcap Where to return the allocated RAM capability
 * @return errval_t 
 */
errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, 1, retcap);
}

/**
 * @brief Free a previously allocated RAM capability (and destroy it)
 * 
 * @param mm The mm instance
 * @param cap The RAM capability to free
 * @return errval_t 
 */
errval_t mm_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    // Remove the node itself from the tree
    struct mm_node *node = __mm_remove_node_tree(mm, cap);
    if (node == NULL) return MM_ERR_NO_PENDING_CAP;
    assert(node->is_pending == false);
    assert(node->is_leaf == true);

    // Add the node back to the list, but collapse it as long as our siblings are not pending
    __mm_collapsing_add_node_list(mm, node);
    
    // Lastly, destroy the pending capability
    err = cap_destroy(cap);
    if (err_is_fail(err)) return err_push(err, MM_ERR_CANNOT_DESTROY_CAP);

    return SYS_ERR_OK;
}
