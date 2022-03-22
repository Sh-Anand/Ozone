#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <spawn/spawn.h>

#include <elf/elf.h>
#include <aos/dispatcher_arch.h>
#include <aos/lmp_chan.h>
#include <aos/aos_rpc.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>

extern struct bootinfo *bi;
extern coreid_t my_core_id;





/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 * 
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
__attribute__((__used__))
static void armv8_set_registers(void *arch_load_info,
                              dispatcher_handle_t handle,
                              arch_registers_state_t *enabled_area,
                              arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t) arch_load_info;

    struct dispatcher_shared_aarch64 * disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}


//the state pointer is just a pointer to store our state. we'll simply pass along the child's paging state so we can map
errval_t elf_allocate_func(void *state, genvaddr_t base, size_t size, uint32_t flags, void **ret) {
    errval_t err;

    struct paging_state *child_state = (struct paging_state *) state;

    //allocate a frame of the requested size
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, size, NULL);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    
    //map frame into specified location in the child's table
    err = paging_map_fixed_attr(child_state, base, frame_cap, size, flags);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);
    
    //map frame into an arbitrary location in our page table
    void *res;
    err = paging_map_frame_attr(get_current_paging_state(), &res, size, frame_cap, flags);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);

    *ret = res;

    return SYS_ERR_OK;
}


/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher called 'argv[0]' with 'argc' arguments.
 * 
 * This function spawns a new dispatcher running the ELF binary called
 * 'argv[0]' with 'argc' - 1 additional arguments. It fills out 'si'
 * and 'pid'.
 * 
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to the spawninfo struct representing
 * the child. It will be filled out by this function. Must not be NULL.
 * \param pid A pointer to a domainid_t variable that will be
 * assigned to by this function. Must not be NULL.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si,
                domainid_t *pid) {
    // TODO: Implement me
    // - Initialize the spawn_info struct
    // - Get the module from the multiboot image
    //   and map it (take a look at multiboot.c)
    // - Setup the child's cspace
    // - Setup the child's vspace
    // - Load the ELF binary
    // - Setup the dispatcher
    // - Setup the environment
    // - Make the new dispatcher runnable

    assert(si != NULL);
    assert(pid != NULL);

    errval_t err;

    //setup the CSpace, variable names are self explanatory
    struct capref child_l1_cnode;
    err = cnode_create_l1(&child_l1_cnode, NULL);

    if(err_is_fail(err))
        return err_push(err, LIB_ERR_CNODE_CREATE);

    struct cnoderef rootcn_taskcn; 
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_TASKCN, &rootcn_taskcn);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);
    
    //created capability for l1_cnode pointing to the right slot in rootcn_taskcn
    struct capref child_l1_cap = {
        .cnode = rootcn_taskcn,
        .slot = TASKCN_SLOT_ROOTCN,
    };
    
    //copy over the created l1 cnode into the taskcn cnode
    cap_copy(child_l1_cap, child_l1_cnode);

    struct cnoderef rootcn_slot_alloc_0, rootcn_slot_alloc_1, rootcn_slot_alloc_2;

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC0, &rootcn_slot_alloc_0);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC0, &rootcn_slot_alloc_1);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC0, &rootcn_slot_alloc_2);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);

    //create SLOT_BASE_PAGE_CN CNode and populate it with L2_CNODE_SLOTS BASE_PAGE_SIZEd RAM caps
    struct cnoderef rootcn_base_page_cn;
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_BASE_PAGE_CN, &rootcn_base_page_cn);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);
    
    struct capref ramcap;
    err = ram_alloc(&ramcap, BASE_PAGE_SIZE * L2_CNODE_SLOTS);
    if(err)
        return err_push(err, LIB_ERR_RAM_ALLOC);

    //we have a range of free slots in the L2 CNode we created. Use it and plug it into cap_retype to prevent using loops as cap retype can be used to split the given cap into multiple caps of given size
    struct capref rootcn_base_page_cn_capref = {
        .cnode = rootcn_base_page_cn,
        .slot = 0, //start from slot 0
    };
    err = cap_retype(rootcn_base_page_cn_capref, ramcap, 0, ObjType_RAM, BASE_PAGE_SIZE, L2_CNODE_SLOTS);
    if(err)
        return err_push(err, LIB_ERR_CAP_RETYPE);
    
    struct cnoderef rootcn_pagecn;
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_PAGECN, &rootcn_pagecn);
    if(err)
        return err_push(err, LIB_ERR_CNODE_CREATE);
    
    //setup VSpace
    //first create root table capability in our space, so we can invoke vnode_create on it
    struct capref child_l0_table_parent;
    err = slot_alloc(&child_l0_table_parent);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_SLOT_ALLOC);

    //create L0 table
    err = vnode_create(child_l0_table_parent, ObjType_VNode_AARCH64_l0);
    if(err)
        return err_push(err, LIB_ERR_VNODE_CREATE);

    //create capref for L0 table of the child, and point it to slot 0 of the rootcn_pagecn cnode
    struct capref child_l0_table = {
        .cnode = rootcn_pagecn,
        .slot = 0,
    };
    
    //copy over created capability into child's space
    err = cap_copy(child_l0_table, child_l0_table_parent);
    if(err)
        return err_push(err, LIB_ERR_CAP_COPY);
    
    //create child's paging state
    struct paging_state *child_paging_state = malloc(sizeof(struct paging_state));
    // TODO: setting start lvaddr to be 0 as we haven't made any mappings that the child doesn't know about yet, however do we need a different start addr?
    paging_init_state_foreign(child_paging_state, 0, child_l0_table_parent, get_default_slot_allocator());
    
    //setup spawninfo
    si->binary_name = argv[0];
    si->next = NULL;

    //find elf binary
    struct mem_region *module = multiboot_find_module(bi, si->binary_name);

    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = module->mrmod_slot,
    };

    //map binary to our page table
    err = paging_map_frame(get_current_paging_state(), &si->mapped_binary, module->mrmod_size, child_frame);

    //verify that the mapped binary contains 0xELF
    assert(IS_ELF(*((struct Elf64_Ehdr *) si->mapped_binary)));

    //parse ELF
    genvaddr_t entry_point; //contains address to the entry point
    err = elf_load(EM_AARCH64, elf_allocate_func, child_paging_state, module->mr_base, module->mrmod_size, &entry_point);
    if(err_is_fail(err))
        return err_push(err, SPAWN_ERR_LOAD);
    
    struct Elf64_Shdr* got = elf64_find_section_header_name((genvaddr_t) si->mapped_binary, module->mrmod_size, ".got");
    assert(got != NULL);

    //void *got_addr = (void *) got->sh_addr; //uncomment this line, commented as it doesn't compile with unused variables
    //Here's the got_addr play around with the dispatcher

    return SYS_ERR_OK;
}


/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher executing 'binary_name'
 * 
 * \param binary_name The name of the binary.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * 
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_name(char *binary_name, struct spawninfo * si,
                            domainid_t *pid) {
    // TODO: Implement me
    // - Get the mem_region from the multiboot image
    // - Fill in argc/argv from the multiboot command line
    // - Call spawn_load_argv

    return LIB_ERR_NOT_IMPLEMENTED;
}



