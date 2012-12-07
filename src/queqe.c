#include "queqe.h"
#include "misc.h"
#include <stdlib.h>
struct isqueqe *add_queqe(struct isqueqe *q)
{
    struct isqueqe  *tmp;
    int id;

    if ( q == NULL )
    {
        q = Malloc(sizeof(struct isqueqe));
        tmp = q;
        tmp -> next = NULL;
        tmp -> id = 0;
        return tmp;
    }
    tmp = q;

    while ( tmp -> next != NULL )
    {
        id = tmp -> id;
        tmp = tmp -> next;
    }
    tmp -> next = Malloc(sizeof(struct isqueqe));
    tmp = tmp -> next;
    tmp -> id++;
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

