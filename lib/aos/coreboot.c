#include <aos/aos.h>
#include <aos/coreboot.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <string.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>

#define ARMv8_KERNEL_OFFSET 0xffff000000000000

#define KERNEL_STACK_PAGES 16

extern struct bootinfo *bi;

struct mem_info {
    size_t                size;      // Size in bytes of the memory region
    void                  *buf;      // Address where the region is currently mapped
    lpaddr_t              phys_base; // Physical base address   
};

/**
 * Load a ELF image into memory.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF will be loaded
 * entry_point:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__))
static errval_t load_elf_binary(genvaddr_t binary, const struct mem_info *mem,
                         genvaddr_t entry_point, genvaddr_t *reloc_entry_point)

{

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point= 0;
    bool loaded = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for(size_t i= 0; i < ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% "PRIx64 ", file size %" PRIu64
                  ", memory size 0x%" PRIx64 " SKIP\n", i, phdr[i].p_vaddr,
                  phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% "PRIx64 ", file size %" PRIu64
              ", memory size 0x%" PRIx64 " LOAD\n", i, phdr[i].p_vaddr,
              phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void *dest = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if(entry_point >= phdr[i].p_vaddr
                 && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
               *reloc_entry_point= (dest_phys + (entry_point - phdr[i].p_vaddr));
               found_entry_point= 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image. 
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF is loaded
 * kernel_:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__))
static errval_t
relocate_elf(genvaddr_t binary, struct mem_info *mem, lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t shnum  = ehdr->e_shnum;
    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for(size_t i= 0; i < shnum; i++) {

        struct Elf64_Shdr *shdr=  &shead[i];
        if(shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if(shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                              " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base= phdr[0].p_vaddr;
            uint64_t segment_load_base=mem->phys_base;
            uint64_t segment_delta= segment_load_base - segment_elf_base;
            uint64_t segment_vdelta= (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if(shdr->sh_type == SHT_REL){
                rsize= sizeof(struct Elf64_Rel);
            } else {
                rsize= sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel= shdr->sh_size / rsize;

            void * reldata = (void*)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for(size_t ii= 0; ii < nrel; ii++) {
                void *reladdr= reldata + ii *rsize;

                switch(shdr->sh_type) {
                    case SHT_REL:
                        DEBUG_PRINTF("SHT_REL unimplemented.\n");
                        return ELF_ERR_PROGHDR;
                    case SHT_RELA:
                    {
                        struct Elf64_Rela *rel= reladdr;

                        uint64_t offset= rel->r_offset;
                        uint64_t sym= ELF64_R_SYM(rel->r_info);
                        uint64_t type= ELF64_R_TYPE(rel->r_info);
                        uint64_t addend= rel->r_addend;

                        uint64_t *rel_target= (void *)offset + segment_vdelta;

                        switch(type) {
                            case R_AARCH64_RELATIVE:
                                if(sym != 0) {
                                    DEBUG_PRINTF("Relocation references a"
                                                 " dynamic symbol, which is"
                                                 " unsupported.\n");
                                    return ELF_ERR_PROGHDR;
                                }

                                /* Delta(S) + A */
                                *rel_target= addend + segment_delta + load_offset;
                                break;

                            default:
                                DEBUG_PRINTF("Unsupported relocation type %d\n",
                                             type);
                                return ELF_ERR_PROGHDR;
                        }
                    }
                    break;
                    default:
                        DEBUG_PRINTF("Unexpected type\n");
                        break;

                }
            }
        }
    }

    return SYS_ERR_OK;
}


static errval_t load_and_relocate(const char *module_name, char *symbol_name, lvaddr_t offset, struct mem_region **module, genvaddr_t *entry_point) {

    //load Elf exactly same as done in spawn for comments check setup_elf() in spawn.c
    errval_t err;
    struct mem_region *module_region = multiboot_find_module(bi, module_name);
    *module = module_region;
    size_t module_size = ROUND_UP(module_region->mrmod_size, BASE_PAGE_SIZE);

    if (module_region == NULL) {
        return CORE_BOOT_ERR_FIND_MODULE;
    }

    struct capref module_frame = {
        .cnode = cnode_module,
        .slot = module_region->mrmod_slot
    };

    void *module_addr;
    err = paging_map_frame(get_current_paging_state(), &module_addr,
                           module_size,
                           module_frame);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_ELF_MAP);

    //get a frame to load the x_driver
    struct capref mem_frame;
    err = frame_alloc(&mem_frame, module_size, NULL);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_FRAME_ALLOC);

    //map frame to our addr space
    void *frame_addr;
    err = paging_map_frame(get_current_paging_state(), &frame_addr, module_size, mem_frame);
    if(err_is_fail(err))
       return err_push(err, CORE_BOOT_ERR_ELF_MAP);

    //get frame info and populate mem_info struct, used with load_elf
    struct mem_info module_info;
    struct frame_identity f_id;
    err = frame_identify(mem_frame, &f_id);
    if(err_is_fail(err))
        return err;
    module_info.buf = frame_addr;
    module_info.phys_base = f_id.base;
    module_info.size = f_id.bytes;

    //find symbol from the ELF : recheck this part, feels weird
    uintptr_t index;
    struct Elf64_Sym *entrypoint = elf64_find_symbol_by_name((genvaddr_t) module_addr, module_size, symbol_name, 0, STT_FUNC, &index);
    if(entrypoint == NULL)
        return err_push(err, ELF_ERR_ALLOCATE);

    //load the elf using given function, get physical address of loaded elf
    genvaddr_t reloc_entry_point;
    err = load_elf_binary((genvaddr_t) module_addr, &module_info, (genvaddr_t) entrypoint->st_value, &reloc_entry_point);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_ELF_MAP);

    //increment the loaded addr by OFFSET to get addr of starting point (I think?)
    reloc_entry_point += offset;

    *entry_point = reloc_entry_point;

    //relocate elf
    err = relocate_elf((genvaddr_t) module_addr, &module_info, offset);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_ELF_MAP);

    return SYS_ERR_OK;
}

static errval_t load_memreg_from_frame(struct armv8_coredata_memreg *memreg, struct capref frame) {
    errval_t err;
    struct frame_identity frame_id;
    err = frame_identify(frame, &frame_id);
    if(err_is_fail(err))
        return err;
    memreg->base = frame_id.base;
    memreg->length = frame_id.bytes;

    return SYS_ERR_OK;
}

static errval_t fill_coredata(struct armv8_core_data *coredata, coreid_t mpid, struct capref kcb, struct capref kernel_stack, genvaddr_t cpu_driver_entry, 
                                struct armv8_coredata_memreg *memreg, struct armv8_coredata_memreg *init_memreg, struct armv8_coredata_memreg *urpc_frame) {
    
    errval_t err;

    //set bootmagic
    coredata->boot_magic = ARMV8_BOOTMAGIC_PSCI;

    //set kernel stack top and bottom
    struct frame_identity kernel_stack_id;
    err = frame_identify(kernel_stack, &kernel_stack_id);
    if(err_is_fail(err))
        return err;
    genpaddr_t kernel_stack_bottom = kernel_stack_id.base;
    genpaddr_t kernel_stack_top = kernel_stack_bottom + kernel_stack_id.bytes;
    coredata->cpu_driver_stack = kernel_stack_top;
    coredata->cpu_driver_stack_limit = kernel_stack_bottom;

    //set cpu driver entry point
    coredata->cpu_driver_entry = cpu_driver_entry;

    //set cmdline arguments (for now passing no args)
    for(int i=0;i<128;i++)
        coredata->cpu_driver_cmdline[i] = 0;

    //set memreg for allocations
    coredata->memory = *memreg;

    //set urpc frame
    coredata->urpc_frame = *urpc_frame;

    //set monitor binary
    coredata->monitor_binary = *init_memreg;

    //set kcb physical addr
    struct frame_identity kcb_id;
    err = invoke_kcb_identify(kcb, &kcb_id);
    if(err_is_fail(err))
        return err;
    coredata->kcb = kcb_id.base;

    //set coreid of caller
    coredata->src_core_id = disp_get_core_id();
    coredata->src_arch_id = disp_get_core_id();

    //set coreid of coredata core
    coredata->dst_core_id = mpid;
    coredata->dst_arch_id = mpid;

    return SYS_ERR_OK;
}

errval_t coreboot(coreid_t mpid,
        const char *boot_driver,
        const char *cpu_driver,
        const char *init,
        struct frame_identity urpc_frame_id)
{

    // Implement me!
    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    //   Note that it should at least OBJSIZE_KCB, and it should also be aligned 
    //   to a multiple of 16k.
    // - Get and load the CPU and boot driver binary.
    // - Relocate the boot and CPU driver. The boot driver runs with a 1:1
    //   VA->PA mapping. The CPU driver is expected to be loaded at the 
    //   high virtual address space, at offset ARMV8_KERNEL_OFFSET.
    // - Allocate a page for the core data struct
    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h
    // - Find the CPU driver entry point. Look for the symbol "arch_init". Put
    //   the address in the core data struct. 
    // - Find the boot driver entry point. Look for the symbol "boot_entry_psci"
    // - Flush the cache.
    // - Call the invoke_monitor_spawn_core with the entry point 
    //   of the boot driver and pass the (physical, of course) address of the 
    //   boot struct as argument.

    DEBUG_PRINTF("INIT CORE : %d\n", mpid);
    errval_t err;

    //Get KCB cap
    struct capref ram_16k_aligned;
    err = ram_alloc_aligned(&ram_16k_aligned, OBJSIZE_KCB, 4*BASE_PAGE_SIZE);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_RAM_ALLOC);
    
    struct capref kcb;
    err = slot_alloc(&kcb);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    
    err = cap_retype(kcb, ram_16k_aligned, 0, ObjType_KernelControlBlock, OBJSIZE_KCB, 1);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_KCB_RETYPE);
    DEBUG_PRINTF("KCB OBTAINED\n", mpid);

    //load and reloc boot_driver elf
    struct mem_region *module_boot_driver;
    genvaddr_t entry_point_boot_driver;
    err = load_and_relocate(boot_driver, "boot_entry_psci", 0, &module_boot_driver, &entry_point_boot_driver);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_ELF_LOAD_RELOCATE);
    DEBUG_PRINTF("LOADED AND RELOCATED BOOT DRIVER\n", mpid);

    //load and reloc cpu_driver elf
    struct mem_region *module_cpu_driver;
    genvaddr_t entry_point_cpu_driver;
    err = load_and_relocate(cpu_driver, "arch_init", ARMv8_KERNEL_OFFSET, &module_cpu_driver, &entry_point_cpu_driver);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_ELF_LOAD_RELOCATE);
    DEBUG_PRINTF("LOADED AND RELOCATED CPU DRIVER\n", mpid);

    //load init and grab physical memory info
    struct armv8_coredata_memreg init_memreg;
    void *init_data;

    struct mem_region *init_region = multiboot_find_module(bi, init);
    struct capref init_frame = {
        .cnode = cnode_module,
        .slot = init_region->mrmod_slot,
    };
    err = load_memreg_from_frame(&init_memreg, init_frame);
    if(err_is_fail(err))
        return err;
    DEBUG_PRINTF("PHYSICAL ADDR OF INIT OBTAINED\n", mpid);

    //map init binary into our addr space
    err = paging_map_frame(get_current_paging_state(), &init_data, ROUND_UP(init_memreg.length, BASE_PAGE_SIZE), init_frame);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);
    DEBUG_PRINTF("MAPPED INIT BINARY\n", mpid);

    //create memory region for CPU driver allocations
    struct armv8_coredata_memreg memreg;
    struct capref allocation_frame;
    size_t size_alloc = ROUND_UP(ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE + elf_virtual_size((lvaddr_t) init_data), BASE_PAGE_SIZE);
    err = frame_alloc(&allocation_frame, size_alloc, NULL);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_FRAME_ALLOC);

    err = load_memreg_from_frame(&memreg, allocation_frame);
    if(err_is_fail(err))
        return err;
    DEBUG_PRINTF("MEMREG FOR CPU DRIVER ALLOCATIONS CREATED\n", mpid);

    //allocate kernel stack
    struct capref kernel_stack_cap;
    size_t kernel_stack_size = KERNEL_STACK_PAGES * BASE_PAGE_SIZE;
    err = frame_alloc(&kernel_stack_cap, kernel_stack_size, NULL);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    DEBUG_PRINTF("KERNEL STACK ALLOCATED\n", mpid);

    void *kernel_stack;
    err = paging_map_frame(get_current_paging_state(), &kernel_stack, kernel_stack_size, kernel_stack_cap);
    if(err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);

    //load provided URPC frame into a coredata memreg
    struct armv8_coredata_memreg urpc_memreg;
    urpc_memreg.base = urpc_frame_id.base;
    urpc_memreg.length = urpc_frame_id.bytes;
    DEBUG_PRINTF("URPC FRAME SET\n", mpid);

    //finally, create the coredata struct
    //we are not mallocing coredata because we want the physical address
    struct armv8_core_data *coredata;
    struct capref coredata_frame;
    size_t coredata_size = BASE_PAGE_SIZE;
    err = frame_alloc(&coredata_frame, coredata_size, NULL);
    if(err_is_fail(err))
        return err;
    DEBUG_PRINTF("COREDATA CREATED\n", mpid);

    err = paging_map_frame(get_current_paging_state(), (void **) &coredata, BASE_PAGE_SIZE, coredata_frame);
    if(err_is_fail(err))
        return err;
    DEBUG_PRINTF("COREDATA MAPPED\n", mpid);

    //fill coredata struct
    err = fill_coredata(coredata, mpid, kcb, kernel_stack_cap, entry_point_cpu_driver, &memreg, &init_memreg, &urpc_memreg);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_FILL_COREDATA);
    DEBUG_PRINTF("COREDATA FILLED\n", mpid);

    //TODO : CLEAR CACHE!!
    arm64_dcache_wb_range((vm_offset_t) coredata, coredata_size);
    arm64_dcache_wb_range((vm_offset_t) kernel_stack, kernel_stack_size);
    arm64_idcache_wbinv_range((vm_offset_t) coredata, coredata_size);
    arm64_idcache_wbinv_range((vm_offset_t) kernel_stack, kernel_stack_size);

    DEBUG_PRINTF("CACHE FLUSHED\n", mpid);

    //finally, invoke kernel cap with boot data pointer
    struct frame_identity coredata_frame_id;
    err = frame_identify(coredata_frame, &coredata_frame_id);
    if(err_is_fail(err))
        return err;

    err = invoke_monitor_spawn_core(mpid, CPU_ARM8, entry_point_boot_driver, coredata_frame_id.base, 0);
    if(err_is_fail(err))
        return err_push(err, CORE_BOOT_ERR_INVOKE);

    DEBUG_PRINTF("CORE BOOTED\n");
    return SYS_ERR_OK;

}
