//
// Created by Zikai Liu on 3/23/22.
//

#include "proc_list.h"
#include <string.h>
#include <unistd.h>

errval_t proc_list_init(struct proc_list *ps)
{
    LIST_INIT(&ps->running);
    LIST_INIT(&ps->free_list);
    ps->pid_upper = 0;
    ps->running_count = 0;
    return SYS_ERR_OK;
}

errval_t proc_list_alloc(struct proc_list *ps, struct proc_node **ret)
{
    assert(ret != NULL);

    struct proc_node *node = NULL;
    if (LIST_EMPTY(&ps->free_list)) {
        if (ps->pid_upper == MAX_DOMAINID) {
            return err_push(PROC_LIST_ERR_OUT_OF_PID, PROC_LIST_ERR_ALLOC);
        }
        node = malloc(sizeof(struct proc_node));
        if (node == NULL) {
            return PROC_LIST_ERR_ALLOC;
        }
        node->pid = ps->pid_upper++;
    } else {
        node = LIST_FIRST(&ps->free_list);
        LIST_REMOVE(node, link);
        // Reuse node->pid
    }
    assert(node != NULL);

    LIST_INSERT_HEAD(&ps->running, node, link);
    ps->running_count++;

    *ret = node;
    return SYS_ERR_OK;
}

static errval_t find_node(const struct proc_list *ps, domainid_t pid, struct proc_node **ret)
{
    struct proc_node *node = NULL;
    LIST_FOREACH(node, &ps->running, link)
    {
        if (node->pid == pid) {
            break;
        }
    }
    if (node == NULL) {
        return PROC_LIST_ERR_NOT_FOUND;
    } else {
        *ret = node;
        return SYS_ERR_OK;
    }
}

errval_t proc_list_delete(struct proc_list *ps, domainid_t pid)
{
    struct proc_node *node;
    errval_t err = find_node(ps, pid, &node);
    if (err_is_fail(err)) {
        return err_push(err, PROC_LIST_ERR_DELETE);
    }
    assert(node != NULL);

    LIST_REMOVE(node, link);
    ps->running_count--;

    node->name[0] = '\0';
    node->dispatcher = NULL_CAP;

    LIST_INSERT_HEAD(&ps->free_list, node, link);
    return SYS_ERR_OK;
}

errval_t proc_list_get_name(struct proc_list *ps, domainid_t pid, char **name)
{
    struct proc_node *node;
    errval_t err = find_node(ps, pid, &node);
    if (err_is_fail(err)) {
        return err_push(err, PROC_LIST_ERR_GET_NAME);
    }
    assert(node != NULL);
    *name = strdup(node->name);
    return SYS_ERR_OK;
}

errval_t proc_list_get_dispatcher(struct proc_list *ps, domainid_t pid, struct capref *dispatcher)
{
    struct proc_node *node;
    errval_t err = find_node(ps, pid, &node);
    if (err_is_fail(err)) {
        return err_push(err, PROC_LIST_ERR_GET_NAME);
    }
    assert(node != NULL);
    *dispatcher = node->dispatcher;
    return SYS_ERR_OK;
}

errval_t proc_list_get_all_pids(struct proc_list *ps, domainid_t **pids, size_t *pid_count)
{
    if (ps->running_count == 0) {
        assert(LIST_EMPTY(&ps->running));
        *pids = NULL;
        *pid_count = 0;
        return SYS_ERR_OK;
    }

    domainid_t *ret = malloc(sizeof(domainid_t) * ps->running_count);
    if (ret == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    size_t i = 0;
    struct proc_node *node = NULL;
    LIST_FOREACH(node, &ps->running, link)
    {
        assert(i < ps->running_count && "ret[] overflows");
        ret[i++] = node->pid;
    }
    assert(i == ps->running_count && "running_count inconsistent");
    *pids = ret;
    *pid_count = ps->running_count;
    return SYS_ERR_OK;
}
