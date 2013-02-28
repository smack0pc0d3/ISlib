#include "queue.h"
#include "misc.h" //Malloc
#include <stdlib.h> //free


struct isqueue *add_queue(struct isqueue *q)
{
    struct isqueue  *tmp, *p;

    //1st time create head
    if ( q == NULL )
    {
        q = Malloc(sizeof(struct isqueue));
        tmp = q;
        tmp -> id = 0;
        tmp -> previous = tmp;
        tmp -> next = NULL;
    }
    tmp = q;

    while ( tmp -> next != NULL )
    {
        tmp -> previous = tmp;
        tmp = tmp -> next;
    }
    p = tmp;
    tmp -> next = Malloc(sizeof(struct isqueue));
    tmp = tmp -> next;
    tmp -> previous = p;
    tmp -> id = pthread_self();
    tmp -> next = NULL;

    return tmp;
}

void delete_queue(struct isqueue *q)
{
    struct isqueue *tmp, *p, *n;

    tmp = q;

    do
    {
        if ( tmp -> id == pthread_self() )
        {
            p = tmp -> previous;
            n = tmp -> next;
            free(tmp);
            p -> next = n;
            if ( n != NULL )
                n -> previous = p;
            return;
        }
        tmp = tmp -> next;
    }while( tmp != NULL );
}

