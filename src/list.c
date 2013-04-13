#include "list.h"
#include "misc.h"

struct list *add_list(struct list **l, size_t size)
{
    struct list  *tmp, *p;

    //1st time create head
    if ( *l == NULL )
    {
        *l = (struct list *)Malloc(size);
        tmp = (struct list *)((unsigned char *)*l+size-sizeof(struct list));
        tmp -> previous = *l;
        tmp -> next = NULL;
        return *l;
    }
    tmp = (struct list *)((unsigned char *)*l+size-sizeof(struct list));

    while ( tmp -> next != NULL )
    {
        tmp = (struct list *)((unsigned char *)tmp -> next+size-sizeof(struct list));
    }
    p = (struct list *)((unsigned char *)tmp-size+sizeof(struct list));
    tmp -> next = Malloc(size);
    tmp = tmp->next;
    tmp = (struct list *)((unsigned char *)tmp+size-sizeof(struct list));
    tmp -> previous = p;
    tmp -> next = NULL;

    return ((struct list *)((unsigned char *)tmp-size+sizeof(struct list)));
}

void delete_list(struct list *l, size_t size)
{
    struct list *tmp, *c;

    tmp = l;

    do
    {
        l = (struct list *)((unsigned char *)l -> next+size-sizeof(struct list));
        free(tmp);
        tmp = l;
    }while ( tmp != (struct list *)NULL );
}

