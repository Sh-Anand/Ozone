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
#include "spawn/proc_mgmt.h"

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

    struct capref cap_to_transfer;

    struct proc_node *proc;
    struct aos_chan *chan;  // should be AOS_CHAN_TYPE_LMP
    struct lmp_chan *lc;    // &chan.lc, helper when added when doing the refactor
};

static inline coreid_t spawn_get_core(domainid_t pid)
{
    STATIC_ASSERT(sizeof(domainid_t) == 4, "sizeof(domainid_t)");
    STATIC_ASSERT(sizeof(coreid_t) == 1, "sizeof(coreid_t)");
    return (coreid_t)FIELD(24, 8, pid);
}

void spawn_init(void (*handler)(void *));

errval_t spawn_kill(domainid_t pid);

errval_t spawn_get_name(domainid_t pid, char **name);

errval_t spawn_get_chan(domainid_t pid, struct aos_chan **chan);

errval_t spawn_get_all_pids(domainid_t **pids, size_t *pid_count);

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid);

errval_t spawn_load_by_name_with_cap(char *binary_name, struct capref cap_to_transfer, struct spawninfo *si, domainid_t *pid);

// Start a child process using the input command line. Fills in si.
errval_t spawn_load_cmdline(const char *cmdline, struct spawninfo *si, domainid_t *pid);

errval_t spawn_load_cmdline_with_cap(const char *cmdline, struct capref cap_to_transfer, struct spawninfo *si, domainid_t *pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid);

errval_t spawn_load_argv_with_cap(int argc, char *argv[], struct capref cap_to_transfer, struct spawninfo *si, domainid_t *pid);

#endif /* _INIT_SPAWN_H_ */
