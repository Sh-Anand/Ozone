#include <stddef.h>

struct free_cluster {
    int cluster;
    struct free_cluster *next;
};

struct free_cluster_list {
    struct free_cluster *head, *tail;
    size_t size;
};

void list_init(struct free_cluster_list **list);

void push_back(struct free_cluster_list *list, int item);

int pop_front(struct free_cluster_list *list);

int is_empty(struct free_cluster_list *list);