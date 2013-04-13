#include "ISlist.h"
#include <stdlib.h> //free
#include <string.h> //memcpy
#include "list.h" //add_list

extern struct ISlist *sniffer_list;
extern struct ISlist *injector_list;


struct ISlist *ISlist_add(struct ISlist **head, struct arguments *args)
{
    struct ISlist  *tmp;

    tmp = (struct ISlist *)add_list((struct list **)head, sizeof(*tmp)); 
    tmp -> shared_packet.iov_base = NULL;
    tmp -> children_num = 0;
    tmp -> children_ack = 0;
    tmp -> args = args;
    tmp -> args -> id = pthread_self();

    //find your father(if any), if you dont, wait till you do
    if ( tmp -> args -> father_id != -1 )
    {
        while ( (tmp -> parent = ISlist_getById(sniffer_list, tmp -> args -> father_id)) == NULL )
        {
            if ( (tmp -> parent = ISlist_getById(injector_list, tmp -> args -> father_id)) != NULL )
                break;
            sleep(1);
        }
        tmp -> parent -> children_num++;
    }
    //set yourself in the key
    pthread_setspecific(key, (void *)tmp);

    return tmp;
}

void ISlist_remove(struct ISlist *q)
{
    struct ISlist *tmp, *p, *n;

    tmp = q;

    do
    {
        if ( tmp -> args -> id == pthread_self() )
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

struct ISlist *ISlist_getById(struct ISlist *head, pthread_t id)
{
    struct ISlist *tmp;

    if ( head == NULL )
        return NULL;
    tmp = head;

    do
    {
        if ( tmp -> args -> id == id )
            return tmp;
        tmp = tmp -> next;
    }while ( tmp != NULL );

    return NULL;
}

void ISlist_send(struct iovec *packet)
{
    struct ISlist *tmp;
    struct timespec t;

    t.tv_sec = 0;
    t.tv_nsec = 9000;

    //find yourself in the ISlists
    /*
    if (( tmp = ISlist_getById(injector_list, pthread_self())) == NULL
            )
        tmp = ISlist_getById(sniffer_list, pthread_self());
    if ( tmp == NULL )
        return;
    */
    tmp = (struct ISlist *)pthread_getspecific(key);
    pthread_mutex_lock(&tmp->lock);

    //if you dont have child return
    if ( !tmp -> children_num )
    {
        pthread_mutex_unlock(&tmp->lock);
        return;
    }
    //make packet shared
    tmp -> shared_packet.iov_base = packet -> iov_base;
    tmp -> shared_packet.iov_len = packet -> iov_len;
    pthread_cond_broadcast(&tmp->cond_var);
    //sleep till all child send ack
    while ( tmp -> children_num != tmp -> children_ack )
        pthread_cond_wait(&tmp->cond_var, &tmp->lock);
    tmp -> children_ack = 0;
    pthread_mutex_unlock(&tmp->lock);
}

void ISlist_recv(struct iovec *packet)
{
    struct ISlist *tmp;

    //find yourself
    /*
    if (( tmp = ISlist_getById(injector_list, pthread_self())) == NULL
            )
        tmp = ISlist_getById(sniffer_list, pthread_self());
    if ( tmp == NULL )
        return;
    */
    tmp = (struct ISlist *)pthread_getspecific(key);
    //if parent doesnt exist
    if ( tmp -> parent == NULL )
        return;
    pthread_mutex_lock(&tmp -> parent -> lock);
    while ( tmp -> parent -> shared_packet.iov_base 
            == tmp -> shared_packet.iov_base )
        pthread_cond_wait(&tmp->parent->cond_var, &tmp->parent->lock);
    tmp -> shared_packet = tmp -> parent -> shared_packet;
    tmp->parent->children_ack++;
    pthread_cond_signal(&tmp->parent->cond_var);
    memcpy(packet -> iov_base, tmp -> shared_packet.iov_base,
            tmp -> shared_packet.iov_len);
    packet -> iov_len = tmp -> shared_packet.iov_len;
    pthread_mutex_unlock(&tmp -> parent -> lock);
}

