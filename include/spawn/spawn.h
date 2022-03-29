/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_SPAWN_H_
#define _INIT_SPAWN_H_

#include "aos/slot_alloc.h"
#include "aos/paging.h"
#include "proc_manage.h"


struct spawninfo {
    // the next in the list of spawned domains
    struct spawninfo *next; 

    // Information about the binary
    char * binary_name;     // Name of the binary

    domainid_t pid;

    // Address of the mapped binary in the parent's address space
    lvaddr_t mapped_binary;

    struct capref rootcn;
    struct cnoderef taskcn;
    struct cnoderef pagecn;

    struct paging_state *child_paging_state;

    struct mem_region *module;
    void *got_addr;
    genvaddr_t pc;

    struct capref dispatcher_cap_in_parent;
    dispatcher_handle_t local_dispatcher_handle;
};

errval_t spawn_init(void);

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo * si,
                            domainid_t *pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si,
                         domainid_t *pid);

errval_t spawn_lookup_by_pid(domainid_t pid, struct spawninfo **ret_si);

errval_t spawn_kill_by_pid(domainid_t pid);

#endif /* _INIT_SPAWN_H_ */
