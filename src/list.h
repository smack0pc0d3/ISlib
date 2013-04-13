#ifndef LIST_H
#define LIST_H
#include <unistd.h>

struct list
{
    void *previous;
    void *next;
};

struct list *add_list(struct list **l, size_t size);
void delete_list(struct list *l, size_t size);
#endif
