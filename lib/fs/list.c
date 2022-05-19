#include <fs/list.h>
#include <stdlib.h>

void list_init(struct free_cluster_list **list) {
    *list = malloc(sizeof(struct free_cluster_list));
    (*list)->head = NULL;
    (*list)->tail = NULL;
    (*list)->size = 0;
}

void push_back(struct free_cluster_list *list, int cluster) {
    struct free_cluster *item = (struct free_cluster *) malloc(sizeof(struct free_cluster));
    item->cluster = cluster;
    item->next = NULL;
    if(list->head == NULL) {
        list->head = item;
        list->tail = item;
    }
    else {
        list->tail->next = item;
        list->tail = item;
    }
    list->size++;
}

int pop_front(struct free_cluster_list *list) {
    if(list->head == NULL)
        return -1;

    int cluster = list->head->cluster;
    struct free_cluster *head = list->head;
    
    if(list->head->next == NULL) {
        list->head = NULL;
        list->tail = NULL;
    }
    else {
        list->head = list->head->next;
    }

    free(head);
    list->size--;
    return cluster;
}

int is_empty(struct free_cluster_list *list) {
    return list->size == 0;
}