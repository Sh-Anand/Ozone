//
// Created by Zikai Liu on 3/23/22.
//

#ifndef AOS_PROC_MGMT_H
#define AOS_PROC_MGMT_H

#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <sys/tree.h>

struct proc_node {
    domainid_t pid;
    struct capref dispatcher;
    char name[DISP_NAME_LEN];
    struct aos_chan chan;
    RB_ENTRY(proc_node) rb_entry;
    LIST_ENTRY(proc_node) link;
};

struct proc_mgmt {
    RB_HEAD(proc_rb_tree, proc_node) running;
    LIST_HEAD(, proc_node) free_list;
    size_t running_count;
    domainid_t pid_upper;
};

coreid_t pid_get_core(domainid_t pid);

errval_t proc_mgmt_init(struct proc_mgmt *ps);

/**
 * Allocate a new process node. PID is filled. lc, dispatcher and name are NOT
 * initialized. The node is inserted into the running list before return.
 * @param ps
 * @param ret
 * @return
 */
errval_t proc_mgmt_alloc(struct proc_mgmt *ps, struct proc_node **ret);

/**
 * Delete a process node by PID.
 * @param ps
 * @param pid
 * @return
 */
errval_t proc_mgmt_delete(struct proc_mgmt *ps, domainid_t pid);

/**
 * Get name of a process by PID.
 * @param ps
 * @param pid
 * @param name  Pointer to a char* which is set as a copy of the name. Should be freed.
 * @return
 */
errval_t proc_mgmt_get_name(struct proc_mgmt *ps, domainid_t pid, char **name);

/**
 * Get dispatcher of a process by PID.
 * @param ps
 * @param pid
 * @param dispatcher
 * @return
 */
errval_t proc_mgmt_get_dispatcher(struct proc_mgmt *ps, domainid_t pid,
                                  struct capref *dispatcher);

/**
 * Get aos channel of a process by PID.
 * @param ps
 * @param pid
 * @param chan
 * @return
 */
errval_t proc_mgmt_get_chan(struct proc_mgmt *ps, domainid_t pid, struct aos_chan **chan);

/**
 * Get an array of all PIDs.
 * @param ps
 * @param pids  Pointer to a domainid_t* which is set as the array. Should be freed.
 * @param pid_count
 * @return
 */
errval_t proc_mgmt_get_all_pids(struct proc_mgmt *ps, domainid_t **pids,
                                size_t *pid_count);

#endif  // AOS_PROC_MGMT_H
