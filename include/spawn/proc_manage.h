//
// Created by Zikai Liu on 3/23/22.
//

#ifndef AOS_PROC_MANAGE_H
#define AOS_PROC_MANAGE_H

#include <aos/capabilities.h>
#include <sys/queue.h>

struct proc_node;

struct proc_state {
    LIST_HEAD(, proc_node) running;
    LIST_HEAD(, proc_node) free_list;
    struct slab_allocator slabs;
    domainid_t pid_upper;
};

errval_t proc_state_init(struct proc_state *ps);

errval_t proc_state_create(struct proc_state *ps, domainid_t *retpid, struct capref dispatcher, const char *name);

errval_t proc_state_remove(struct proc_state *ps, domainid_t pid);

typedef void (*proc_enum_callback_t)(domainid_t pid, struct capref dispatcher, const char *name);

errval_t proc_state_enum(struct proc_state *ps, proc_enum_callback_t callback);

#endif  // AOS_PROC_MANAGE_H
