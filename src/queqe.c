#include "queqe.h"
#include "misc.h" //Malloc
#include <stdlib.h> //free

struct isqueqe *add_queqe(struct isqueqe *q)
{
    struct isqueqe  *tmp;

    if ( q == NULL )
    {
        q = Malloc(sizeof(struct isqueqe));
        tmp = q;
        tmp -> id = pthread_self();
        tmp -> next = NULL;
        return tmp;
    }
    tmp = q;

    while ( tmp -> next != NULL )
    {
        tmp = tmp -> next;
    }
    tmp -> next = Malloc(sizeof(struct isqueqe));
    tmp = tmp -> next;
    tmp -> id = pthread_self();
    tmp -> next = NULL;
    return tmp;
}

void delete_queqe(struct isqueqe *q)
{
    struct isqueqe *tmp;

    tmp = q;

    do
    {
        q = q -> next;
        free(tmp);
        tmp = q;
    }while( tmp != NULL );
}

