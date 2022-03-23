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
__attribute__((__used__)) static void
armv8_set_registers(void *arch_load_info, dispatcher_handle_t handle,
                    arch_registers_state_t *enabled_area,
                    arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t)arch_load_info;

    struct dispatcher_shared_aarch64 *disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}

static errval_t alloc_zeroed_frame(size_t bytes, struct capref *frame_cap,
                                   void **local_vaddr, errval_t alloc_errcode,
                                   errval_t map_errcode)
{
    assert(frame_cap != NULL);
    assert(local_vaddr != NULL);

    errval_t err;

    // Create the frame
    struct capref frame;
    err = frame_alloc(&frame, bytes, NULL);
    if (err_is_fail(err)) {
        return err_push(err, alloc_errcode);
    }

    // Map the frame to self
    dispatcher_handle_t handle = 0;
    err = paging_map_frame(get_current_paging_state(), (void **)&handle, bytes, frame);
    if (err_is_fail(err)) {
        return err_push(err, map_errcode);
    }
    assert(handle != 0);
    memset((void *)handle, 0, bytes);

    *frame_cap = frame;
    *local_vaddr = (void *)handle;
    return SYS_ERR_OK;
}

static errval_t setup_dispatcher(struct spawninfo *si, const char *name,
                                 genvaddr_t pc, genvaddr_t got_addr)
{
    errval_t err;

    // Alloc the dispatcher frame and map to self
    struct capref dispframe;
    dispatcher_handle_t handle = 0;
    err = alloc_zeroed_frame(DISPATCHER_FRAME_SIZE, &dispframe, (void **)&handle,
                             SPAWN_ERR_CREATE_DISPATCHER_FRAME,
                             SPAWN_ERR_MAP_DISPATCHER_TO_SELF);
    if (err_is_fail(err)) {
        return err;
    }
    assert(handle != 0);
    si->local_dispatcher_handle = handle;

    // Setup the dispatcher
    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle);

    // Core id of the process
    disp_gen->core_id = my_core_id;

    // Virtual address of the dispatcher frame in child’s VSpace
    disp->udisp = CHILD_DISPFRAME_VADDR;

    // Start in disabled mode
    disp->disabled = 1;

    // A name (for debugging)
    // TODO: test a name with len >= DISP_NAME_LEN
    strncpy(disp->name, name, DISP_NAME_LEN - 1);  // NUL terminator
    // The frame is memset to 0 so there should be NUL at the end

    // Set program counter (where it should start to execute)
    disabled_area->named.pc = pc;

    // Initialize offset registers
    armv8_set_registers((void *)got_addr, handle, enabled_area, disabled_area);

    // We won’t use error handling frames
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    // Install the frame to the child's VSpace
    struct capref child_dispframe_slot = {
        .cnode = si->rootcn_taskcn,
        .slot = TASKCN_SLOT_DISPFRAME,
    };
    err = cap_copy(child_dispframe_slot, dispframe);
    if (err_is_fail(err)) {
        // FIXME: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_DOMAIN_CAP);
    }

    // TODO: map the frame to the child's vspace

    return SYS_ERR_OK;
}


static errval_t setup_arguments(struct spawninfo *si, int argc, char *argv[])
{
    errval_t err;


    // Alloc the arg page and map to self
    struct capref argpage;
    struct spawn_domain_params *params = 0;
    err = alloc_zeroed_frame(BASE_PAGE_SIZE, &argpage, (void **)&params,
                             SPAWN_ERR_CREATE_ARGSPG,
                             SPAWN_ERR_MAP_ARGSPG_TO_SELF);
    if (err_is_fail(err)) {
        return err;
    }
    assert(params != 0);

    // TODO: map the frame to the child's vspace

    // Setup spawn_domain_params and copy arguments
    params->argc = argc;
    char *offset = TODO_CHILD_MAPPING_OFFSET + sizeof(spawn_domain_params);
    for (int i = 0; i < argc; i++) {
        size_t copy_len = strlen(argv[i]) + 1;  // NUL terminator
        if (offset + copy_len >= (char *)(TODO_CHILD_MAPPING_OFFSET + BASE_PAGE_SIZE)) {
            return SPAWN_ERR_ARGSPG_OVERFLOW;
        }
        strcpy(offset, argv[i]);
        params->argv[i] = offset;

        offset += copy_len;
    }
    params->argv[params->argc] = 0;  // NULL terminator for argv
    // TODO: envp empty?
    params->envp[0] = 0;  // NULL terminator for envp
    // TODO: other fields?

    // Install the frame to the child's VSpace
    struct capref child_argspace_slot = {
        .cnode = si->rootcn_taskcn,
        .slot = TASKCN_SLOT_ARGSPAGE,
    };
    err = cap_copy(child_argspace_slot, argpage);
    if (err_is_fail(err)) {
        // FIXME: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_ARGCN);
    }


}

static errval_t start_dispatcher(struct spawninfo *si) {
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(si->local_dispatcher_handle);
    registers_set_param(enabled_area, TODO_CHILD_MAPPING_OFFSET);
    invoke_dispatcher(si->)
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
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
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

    return LIB_ERR_NOT_IMPLEMENTED;
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
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid)
{
    // TODO: Implement me
    // - Get the mem_region from the multiboot image
    // - Fill in argc/argv from the multiboot command line
    // - Call spawn_load_argv

    return LIB_ERR_NOT_IMPLEMENTED;
}
