//
// Created by Zikai Liu on 3/23/22.
//

#include <spawn/proc_manage.h>
#include <string.h>

#define PID_START 1

struct proc_node {
    domainid_t pid;
    struct capref dispatcher;
    char name[DISP_NAME_LEN];
    LIST_ENTRY(proc_node) link;
};

errval_t proc_list_init(struct proc_list *ps)
{
    LIST_INIT(&ps->running);
    LIST_INIT(&ps->free_list);
    slab_init(&ps->slabs, sizeof(struct proc_node), slab_default_refill);
    ps->pid_upper = PID_START;
    return SYS_ERR_OK;
}

errval_t proc_list_insert(struct proc_list *ps, domainid_t pid,
                           struct capref dispatcher, const char *name)
{
    struct proc_node *node = NULL;
    if (LIST_EMPTY(&ps->free_list)) {
        node = slab_alloc(&ps->slabs);
        if (node == NULL) {
            return LIB_ERR_SLAB_ALLOC_FAIL;
        }
    } else {
        node = LIST_FIRST(&ps->free_list);
        LIST_REMOVE(node, link);
    }
    assert(node != NULL);

    node->pid = pid;
    node->dispatcher = dispatcher;
    strncpy(node->name, name, DISP_NAME_LEN);
    node->name[DISP_NAME_LEN - 1] = '\0';

    LIST_INSERT_HEAD(&ps->running, node, link);
    return SYS_ERR_OK;
}

errval_t proc_list_remove(struct proc_list *ps, domainid_t pid)
{
    struct proc_node *node = NULL;
    LIST_FOREACH(node, &ps->running, link)
    {
        if (node->pid == pid) {
            break;
        }
    }
    if (node != NULL) {
        LIST_REMOVE(node, link);
        LIST_INSERT_HEAD(&ps->free_list, node, link);
        return SYS_ERR_OK;
    } else {
        return SPAWN_ERR_DOMAIN_NOTFOUND;  // XXX: change to a more precise error
    }
}

errval_t proc_list_enum(struct proc_list *ps, proc_enum_callback_t callback)
{
    if (callback == NULL) {
        return ERR_INVALID_ARGS;
    }
    struct proc_node *node;
    LIST_FOREACH(node, &ps->running, link)
    {
        callback(node->pid, node->dispatcher, node->name);
    }
    return SYS_ERR_OK;
}