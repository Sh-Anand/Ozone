//
// Created by Zikai Liu on 3/23/22.
//

#ifndef AOS_PROC_LIST_H
#define AOS_PROC_LIST_H

#include <aos/capabilities.h>
#include <aos/lmp_chan.h>
#include <sys/queue.h>

struct proc_node {
    domainid_t pid;
    struct capref dispatcher;
    char name[DISP_NAME_LEN];
    struct lmp_chan lc;
    LIST_ENTRY(proc_node) link;
};

struct proc_list {
    LIST_HEAD(, proc_node) running;
    LIST_HEAD(, proc_node) free_list;
    size_t running_count;
    domainid_t pid_upper;
};

errval_t proc_list_init(struct proc_list *ps);

/**
 * Allocate a new process node. PID is filled. lc is initialized. dispatcher and name are
 * uninitialized. The node is inserted into the running
 * list before return.
 * @param ps
 * @param ret
 * @return
 */
errval_t proc_list_alloc(struct proc_list *ps, struct proc_node **ret);

/**
 * Delete a process node by PID.
 * @param ps
 * @param pid
 * @return
 */
errval_t proc_list_delete(struct proc_list *ps, domainid_t pid);

/**
 * Get name of a process by PID.
 * @param ps
 * @param pid
 * @param name  Pointer to a char* which is set as a copy of the name. Should be freed.
 * @return
 */
errval_t proc_list_get_name(struct proc_list *ps, domainid_t pid, char **name);

/**
 * Get an array of all PIDs.
 * @param ps
 * @param pids  Pointer to a domainid_t* which is set as the array. Should be freed.
 * @param pid_count
 * @return
 */
errval_t proc_list_get_all_pids(struct proc_list *ps, domainid_t **pids,
                                size_t *pid_count);

#endif  // AOS_PROC_LIST_H
