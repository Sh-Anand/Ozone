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


struct spawninfo {
    // the next in the list of spawned domains
    struct spawninfo *next;

    // Information about the binary
    char *binary_name;  // Name of the binary

    domainid_t pid;

    // Address of the mapped binary in the parent's address space
    lvaddr_t mapped_binary;

    struct capref rootcn;
    struct cnoderef taskcn;
    struct cnoderef pagecn;

    struct paging_state *child_paging_state;  // XXX: to be free

    struct mem_region *module;
    void *got_addr;
    genvaddr_t pc;

    struct capref dispatcher_cap_in_parent;
    dispatcher_handle_t local_dispatcher_handle;

    struct lmp_chan *lc;
};

errval_t spawn_kill(domainid_t pid);

errval_t spawn_get_name(domainid_t pid, char **name);

errval_t spawn_get_all_pids(domainid_t **pids, size_t *pid_count);

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid);

// Start a child process using the input command line. Fills in si.
errval_t spawn_load_cmdline(const char *cmdline, struct spawninfo *si, domainid_t *pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid);

#endif /* _INIT_SPAWN_H_ */
