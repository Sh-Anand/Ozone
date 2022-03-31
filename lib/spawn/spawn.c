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

#include "proc_list.h"

extern char **environ;
extern struct bootinfo *bi;
extern coreid_t my_core_id;

static struct capref local_endpoint_cap;
static struct lmp_endpoint *binding_recv_ep = NULL;
#define LOCAL_ENDPOINT_BUF_LEN 1024

static void (*rpc_handler)(void *) = NULL;

#define PID_START 1000
static struct proc_list pl = {
    .running = LIST_HEAD_INITIALIZER(),
    .free_list = LIST_HEAD_INITIALIZER(),
    .pid_upper = PID_START,
    .running_count = 0,
};
#define PROC_ENDPOINT_BUF_LEN 16

// TODO: these address works?
#define CHILD_DISPFRAME_VADDR (0x200000)
#define CHILD_ARGFRAME_VADDR (0x200000 + DISPATCHER_FRAME_SIZE)

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

// Allocate a frame, memset with 0, and map to self
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

// the state pointer is just a pointer to store our state. we'll simply pass along the
// child's paging state so we can map
static errval_t elf_allocate_func(void *state, genvaddr_t base, size_t size,
                                  uint32_t flags, void **ret)
{
    errval_t err;
    // we page align the base address and the size
    struct paging_state *child_state = (struct paging_state *)state;

    genvaddr_t fbase = base / BASE_PAGE_SIZE * BASE_PAGE_SIZE;
    size_t esize = (size + base - fbase + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE
                   * BASE_PAGE_SIZE;
    // Allocate a frame of the requested size
    struct capref frame_cap;
    err = frame_alloc(&frame_cap, esize, NULL);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_FRAME_ALLOC);


    // Map frame into specified location in the child's table
    err = paging_map_fixed_attr(child_state, fbase, frame_cap, esize, flags);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);

    // Map frame into an arbitrary location in our page table
    void *res;

    err = paging_map_frame_attr(get_current_paging_state(), &res, esize, frame_cap,
                                VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_PAGING_MAP);

    *ret = res + base - fbase;

    return SYS_ERR_OK;
}


static errval_t setup_dispatcher(struct spawninfo *si)
{
    errval_t err;

    // Create the dispatcher cap in child and copy to parent
    struct capref child_dispatcher_slot = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_DISPATCHER,
    };
    err = dispatcher_create(child_dispatcher_slot);
    if (err_is_fail(err)) {
        return err;
    }

    err = slot_alloc(&si->dispatcher_cap_in_parent);
    if (err_is_fail(err)) {
        // FIXME: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_DOMAIN_CAP);
    }

    err = cap_copy(si->dispatcher_cap_in_parent, child_dispatcher_slot);
    if (err_is_fail(err)) {
        // FIXME: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_DOMAIN_CAP);
    }

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

    // Setup the dispatcher control block
    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle);

    // Core id of the process
    disp_gen->core_id = my_core_id;

    // PID
    disp_gen->domain_id = si->pid;

    // Virtual address of the dispatcher frame in child’s VSpace
    disp->udisp = CHILD_DISPFRAME_VADDR;

    // Start in disabled mode
    disp->disabled = 1;

    // A name (for debugging)
    // TODO: test a name with len >= DISP_NAME_LEN
    strncpy(disp->name, si->binary_name, DISP_NAME_LEN - 1 /* NUL terminator */);
    // The frame is memset to 0 so there should be NUL at the end

    si->binary_name = disp->name;  // reset the pointer to this persisting storage

    // Set program counter (where it should start to execute)
    disabled_area->named.pc = si->pc;

    // Initialize offset registers
    armv8_set_registers(si->got_addr, handle, enabled_area, disabled_area);

    // We won’t use error handling frames
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    // Install the frame to the child's VSpace
    struct capref child_dispframe_slot = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_DISPFRAME,
    };
    err = cap_copy(child_dispframe_slot, dispframe);
    if (err_is_fail(err)) {
        // FIXME: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_DOMAIN_CAP);
    }

    // Map the frame to the child's vspace
    err = paging_map_fixed_attr(si->child_paging_state, CHILD_DISPFRAME_VADDR, dispframe,
                                DISPATCHER_FRAME_SIZE, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_MAP_DISPATCHER_TO_NEW);
    }

    return SYS_ERR_OK;
}

static errval_t refill_ep_recv_slot(void)
{
    struct capref ep_recv_slot;
    errval_t err = slot_alloc(&ep_recv_slot);
    if (err_is_fail(err)) {
        return err;
    }
    lmp_endpoint_set_recv_slot(binding_recv_ep, ep_recv_slot);
    return SYS_ERR_OK;
}

static void binding_handler(void *arg)
{
    struct spawninfo *si = arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    errval_t err;

    // Try to receive a message
    err = lmp_endpoint_recv(binding_recv_ep, &msg.buf, &cap);
    if (err_is_fail(err)) {
        if (lmp_err_is_transient(err)) {
            // Re-register
            err = lmp_endpoint_register(binding_recv_ep, get_default_waitset(),
                                        MKCLOSURE(binding_handler, arg));
            if (err_is_ok(err))
                return;  // otherwise, fall through
        }
        USER_PANIC_ERR(err_push(err, MON_ERR_IDC_BIND_LOCAL),  // XXX: another error
                       "unhandled error in binding_handler");
    }

    // XXX: no checking for now, might be risky if user program exploit this endpoint
    DEBUG_PRINTF("spawn: receive binding request from process %lu\n", msg.words[0])
    err = lmp_chan_accept(si->lc, PROC_ENDPOINT_BUF_LEN, cap);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "binding_handler: fail to accept");
    }

    // Assign initial slot for incoming cap
    struct capref new_init_ep_slot;
    err = slot_alloc(&new_init_ep_slot);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "binding_handler: fail to alloc slot");
    }
    lmp_chan_set_recv_slot(si->lc, new_init_ep_slot);

    // Start receiving on the channel
    err = lmp_chan_register_recv(si->lc, get_default_waitset(),
                                MKCLOSURE(rpc_handler, si->lc));
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "binding_handler: fail to register channel recv");
    }


    // Ack with the new endpoint
    err = lmp_chan_send0(si->lc, LMP_SEND_FLAGS_DEFAULT, si->lc->local_cap);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "binding_handler: fail to send");
    }
    refill_ep_recv_slot();
    // No need to re-register
}

static errval_t create_local_lmp_ep_if_not_yet(void) {
    errval_t err;

    // Create local endpoint if not done yet
    if (binding_recv_ep == NULL) {
        err = endpoint_create(LOCAL_ENDPOINT_BUF_LEN, &local_endpoint_cap,
                              &binding_recv_ep);
        if (err_is_fail(err)) {
            return err;
        }
        assert(!capref_is_null(local_endpoint_cap));
        assert(binding_recv_ep != NULL);

        // Setup initial recv slot (recv handler will refill automatically)
        refill_ep_recv_slot();
    }
    return SYS_ERR_OK;
}

static errval_t setup_endpoint(struct spawninfo *si)
{
    if (rpc_handler == NULL) {
        return SPAWN_ERR_RPC_HANDLER_NOT_SET;
    }

    errval_t err;

    // Create local endpoint if not done yet
    err = create_local_lmp_ep_if_not_yet();
    if (err_is_fail(err)) {
        return err;
    }
    assert(binding_recv_ep != NULL);

    // Set receiver on the endpoint
    assert(si->lc != NULL);
    si->lc->connstate = LMP_BIND_WAIT;
    err = lmp_endpoint_register(binding_recv_ep, get_default_waitset(),
                                MKCLOSURE(binding_handler, si));
    if (err_is_fail(err)) {
        return err;
    }

    struct capref child_initep_slot = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_INITEP,
    };
    err = cap_copy(child_initep_slot, local_endpoint_cap);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_COPY_DOMAIN_CAP);  // XXX: not this one
    }

    return SYS_ERR_OK;
}


static errval_t setup_arguments(struct spawninfo *si, int argc, char *argv[])
{
    errval_t err;

    // Alloc the arg page and map to self
    struct capref argpage;
    struct spawn_domain_params *params = 0;
    err = alloc_zeroed_frame(BASE_PAGE_SIZE, &argpage, (void **)&params,
                             SPAWN_ERR_CREATE_ARGSPG, SPAWN_ERR_MAP_ARGSPG_TO_SELF);
    if (err_is_fail(err)) {
        return err;
    }
    assert(params != 0);

    // Map the arg page to the child's vspace
    err = paging_map_fixed_attr(si->child_paging_state, CHILD_ARGFRAME_VADDR, argpage,
                                BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_MAP_ARGSPG_TO_NEW);
    }

    // Setup spawn_domain_params and copy arguments and envs
    size_t offset = sizeof(struct spawn_domain_params);
    int i;

    params->argc = argc;
    for (i = 0; i < argc; i++) {
        size_t copy_len = strlen(argv[i]) + 1;  // NUL terminator
        if (offset + copy_len >= BASE_PAGE_SIZE) {
            return SPAWN_ERR_ARGSPG_OVERFLOW;
        }
        strcpy(((char *)params + offset), argv[i]);                 // parent address
        params->argv[i] = (char *)(CHILD_ARGFRAME_VADDR + offset);  // child address

        offset += copy_len;
    }
    params->argv[params->argc] = 0;  // NULL terminator for argv

    for (i = 0; i < MAX_ENVIRON_VARS && environ[i] != 0; i++) {
        size_t copy_len = strlen(environ[i]) + 1;  // NUL terminator
        if (offset + copy_len >= BASE_PAGE_SIZE) {
            return SPAWN_ERR_ARGSPG_OVERFLOW;
        }
        strcpy(((char *)params + offset), environ[i]);              // parent address
        params->envp[i] = (char *)(CHILD_ARGFRAME_VADDR + offset);  // child address

        offset += copy_len;
    }
    params->envp[i] = 0;  // NULL terminator for envp

    // Install the frame to the child's VSpace
    struct capref child_argspace_slot = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_ARGSPAGE,
    };
    err = cap_copy(child_argspace_slot, argpage);
    if (err_is_fail(err)) {
        // XXX: no corresponding err or doing the wrong thing?
        return err_push(err, SPAWN_ERR_COPY_ARGCN);
    }

    return SYS_ERR_OK;
}

static errval_t start_dispatcher(struct spawninfo *si)
{
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(
        si->local_dispatcher_handle);
    registers_set_param(enabled_area, CHILD_ARGFRAME_VADDR);

    struct capref child_rootvn_cap = {
        .cnode = si->pagecn,
        .slot = 0,
    };

    struct capref child_dispframe_cap = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_DISPFRAME,
    };

    return invoke_dispatcher(si->dispatcher_cap_in_parent, cap_dispatcher, si->rootcn,
                             child_rootvn_cap, child_dispframe_cap, true);
}

static errval_t setup_cspace(struct spawninfo *si)
{
    errval_t err;

    // ROOTCN
    struct capref child_l1_cnode;
    err = cnode_create_l1(&child_l1_cnode, NULL);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_ROOTCN);
    }
    si->rootcn = child_l1_cnode;

    // ROOTCN_SLOT_TASKCN
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_TASKCN, &si->taskcn);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_TASKCN);
    }

    // Created capability for l1_cnode pointing to the right slot in taskcn
    struct capref child_rootcn_slot = {
        .cnode = si->taskcn,
        .slot = TASKCN_SLOT_ROOTCN,
    };

    // Copy over the created l1 cnode into the taskcn cnode
    cap_copy(child_rootcn_slot, child_l1_cnode);

    // ROOTCN_SLOT_SLOT_ALLOC0-2
    struct cnoderef rootcn_slot_alloc_0, rootcn_slot_alloc_1, rootcn_slot_alloc_2;
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC0,
                                  &rootcn_slot_alloc_0);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC1,
                                  &rootcn_slot_alloc_1);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_SLOT_ALLOC2,
                                  &rootcn_slot_alloc_2);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    }

    // Create SLOT_BASE_PAGE_CN and populate it with L2_CNODE_SLOTS BASE_PAGE_SIZEd RAM
    struct cnoderef rootcn_base_page_cn;
    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_BASE_PAGE_CN,
                                  &rootcn_base_page_cn);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_SMALLCN);
    }

    struct capref ramcap;
    err = ram_alloc(&ramcap, BASE_PAGE_SIZE * L2_CNODE_SLOTS);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_FILL_SMALLCN);
    }

    // we have a range of free slots in the L2 CNode we created. Use it and plug it into
    // cap_retype to prevent using loops as cap retype can be used to split the given cap
    // into multiple caps of given size
    struct capref rootcn_base_page_cn_capref = {
        .cnode = rootcn_base_page_cn,
        .slot = 0,  // start from slot 0
    };
    err = cap_retype(rootcn_base_page_cn_capref, ramcap, 0, ObjType_RAM, BASE_PAGE_SIZE,
                     L2_CNODE_SLOTS);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_FILL_SMALLCN);
    }

    err = cnode_create_foreign_l2(child_l1_cnode, ROOTCN_SLOT_PAGECN, &si->pagecn);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_PAGECN);
    }

    return SYS_ERR_OK;
}

static errval_t setup_vspace(struct spawninfo *si)
{
    errval_t err;

    // Create root table capability in our space, so we can invoke vnode_create on it
    struct capref child_l0_table_parent;
    err = slot_alloc(&child_l0_table_parent);
    if (err_is_fail(err)) {
        return err;
    }

    // Create L0 table
    err = vnode_create(child_l0_table_parent, ObjType_VNode_AARCH64_l0);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_CREATE_VNODE);
    }

    // Copy the created capability into child's space
    struct capref child_l0_table = {
        .cnode = si->pagecn,
        .slot = 0,
    };
    err = cap_copy(child_l0_table, child_l0_table_parent);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_COPY_VNODE);
    }

    // create child's paging state
    si->child_paging_state = malloc(sizeof(struct paging_state));
    // TODO: setting start lvaddr to be 0 as we haven't made any mappings that the child
    // doesn't know about yet, however do we need a different start addr?
    paging_init_state_foreign(si->child_paging_state, 0, child_l0_table_parent,
                              get_default_slot_allocator());

    return SYS_ERR_OK;
}

static errval_t setup_elf(struct spawninfo *si)
{
    errval_t err;

    assert(si->module != NULL);
    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = si->module->mrmod_slot,
    };

    // map binary to our page table
    err = paging_map_frame(get_current_paging_state(), (void **)&si->mapped_binary,
                           (si->module->mrmod_size + BASE_PAGE_SIZE - 1) / BASE_PAGE_SIZE
                               * BASE_PAGE_SIZE,
                           child_frame);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_ELF_MAP);
    }
    assert(si->mapped_binary != 0);

    // Verify that the mapped binary contains 0xELF
    if (!IS_ELF(*((struct Elf64_Ehdr *)si->mapped_binary))) {
        return SPAWN_ERR_ELF_MAP;  // XXX: invalid elf
        // TODO: test it
    }

    // Parse ELF
    err = elf_load(EM_AARCH64, elf_allocate_func, si->child_paging_state,
                   si->mapped_binary, si->module->mrmod_size, &si->pc);
    // TODO: not unmapped in parent for now
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_LOAD);
    }

    struct Elf64_Shdr *got = elf64_find_section_header_name(
        (genvaddr_t)si->mapped_binary, si->module->mrmod_size, ".got");
    if (got == NULL) {
        return SPAWN_ERR_ELF_MAP;  // XXX: fail to find got address
    }
    si->got_addr = (void *)got->sh_addr;

    return SYS_ERR_OK;
}

/**
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

    si->binary_name = argv[0];
    // Temporary, will be set to persisting string in setup_dispatcher

    // Get the module from the multiboot image
    si->module = multiboot_find_module(bi, argv[0]);
    if (si->module == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }

    errval_t err;
    struct proc_node *node;
    err = proc_list_alloc(&pl, &node);
    if (err_is_fail(err)) {
        return err;
    }
    strncpy(node->name, si->binary_name, DISP_NAME_LEN - 1);
    node->name[DISP_NAME_LEN - 1] = '\0';
    si->pid = node->pid;
    *pid = si->pid;
    assert(node->lc.connstate == LMP_DISCONNECTED);
    si->lc = &node->lc;  // will be filled by setup_endpoint()

    // Setup CSpace
    err = setup_cspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_SETUP_CSPACE);
    }

    // Setup VSpace
    err = setup_vspace(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_VSPACE_INIT);
    }

    // Setup ELF
    err = setup_elf(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_ELF_MAP);
    }

    // Setup dispatcher
    err = setup_dispatcher(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_SETUP_DISPATCHER);
    }
    node->dispatcher = si->dispatcher_cap_in_parent;

    // Setup endpoint
    err = setup_endpoint(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_SETUP_DISPATCHER);  // XXX: not this one
    }
    assert(node->lc.connstate == LMP_BIND_WAIT);

    // Setup arguments
    err = setup_arguments(si, argc, argv);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_GET_CMDLINE_ARGS);  // XXX: not this one
    }

    // Start
    err = start_dispatcher(si);
    if (err_is_fail(err)) {
        return err_push(err, SPAWN_ERR_ELF_MAP);
    }

    assert(si->lc->connstate == LMP_BIND_WAIT);
    while (si->lc->connstate != LMP_CONNECTED) {
        err = event_dispatch(get_default_waitset());
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in spawn event_dispatch loop");
            return err_push(err, LIB_ERR_BIND_LMP_REQ);  // XXX: not this one
        }
    }

    return SYS_ERR_OK;
}


/**
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
    struct mem_region *module = multiboot_find_module(bi, binary_name);
    if (module == NULL) {
        return SPAWN_ERR_FIND_MODULE;
    }

    // Get command line arguments
    const char *opts = multiboot_module_opts(module);
    if (opts == NULL) {
        return SPAWN_ERR_GET_CMDLINE_ARGS;
    }

    return spawn_load_cmdline(opts, si, pid);
}

errval_t spawn_load_cmdline(const char *cmdline, struct spawninfo *si, domainid_t *pid)
{
    int argc = 0;
    char *buf;
    char **argv = make_argv(cmdline, &argc, &buf);

    errval_t err = spawn_load_argv(argc, argv, si, pid);
    // Fall through on either success or failure
    free(argv);
    free(buf);
    return err;
}

void spawn_set_rpc_handler(void (*handler)(void *)) {
    rpc_handler = handler;
}

errval_t spawn_kill(domainid_t pid) {
    errval_t err;
    struct capref dispatcher;
    err = proc_list_get_dispatcher(&pl, pid, &dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, PROC_MGMT_ERR_KILL);
    }
    err = invoke_dispatcher_stop(dispatcher);
    if (err_is_fail(err)) {
        return err_push(err, PROC_MGMT_ERR_KILL);
    }
    return SYS_ERR_OK;
}

errval_t spawn_get_name(domainid_t pid, char **name) {
    return proc_list_get_name(&pl, pid, name);
}

errval_t spawn_get_all_pids(domainid_t **pids, size_t *pid_count) {
    return proc_list_get_all_pids(&pl, pids, pid_count);
}