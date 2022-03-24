//
// Created by Zikai Liu on 3/23/22.
//

#ifndef AOS_PROC_MANAGE_H
#define AOS_PROC_MANAGE_H

#include <aos/capabilities.h>
#include <sys/queue.h>

struct proc_node;

struct proc_list {
    LIST_HEAD(, proc_node) running;
    LIST_HEAD(, proc_node) free_list;
    struct slab_allocator slabs;
    domainid_t pid_upper;
};

errval_t proc_list_init(struct proc_list *ps);

errval_t proc_list_insert(struct proc_list *ps, domainid_t pid, struct capref dispatcher, const char *name);

errval_t proc_list_remove(struct proc_list *ps, domainid_t pid);

typedef void (*proc_enum_callback_t)(domainid_t pid, struct capref dispatcher, const char *name);

errval_t proc_list_enum(struct proc_list *ps, proc_enum_callback_t callback);

#endif  // AOS_PROC_MANAGE_H
