#ifndef QUEQE_H
#define QUEQE_H

#include <net/if.h> //struct iovec
#include <linux/if_packet.h> //struct tpacket_req
#include <pthread.h> //pthread_t
#include "misc.h"

//extern struct ISlist *sniffer_list;
//extern struct ISlist *injector_list;

//TODO make a pointer associated with thread key pointing at index in
//list
pthread_key_t key;
int key_init;

//i must make the children num of a parent -1 for each child diying
struct ISlist
{
    struct ISlist       *parent; //what we waiting for
    struct tpacket_req  *packet_req; //request space for mmap
    unsigned char       *ps_hdr_start; //available space for packet
    struct iovec        shared_packet; //sharing packet addr
    int                 fd; //fd for our socket
    int                 children_num; //num of children
    int                 children_ack; //ack from children
    pthread_mutex_t     lock; //lock 
    pthread_cond_t      cond_var; //condition variable for packet
    struct arguments    *args;
    struct ISlist       *previous;
    struct ISlist   	  *next;
};

//add a new element to the list, returns the addr of the new element
struct ISlist *ISlist_add(struct ISlist **head, struct arguments *args);
//sends a packet to children (if any)
void ISlist_send(struct iovec *packet);
//wait till father sends a packet
void ISlist_recv(struct iovec *packet);
//find a thread in list by ud
struct ISlist *ISlist_getById(struct ISlist *head, pthread_t id);
//void setup_ISlist(struct ISlist *q, void(*functionptr)(struct iovec *, char **), pthread_t father_id);
//remove the current addr from list
void ISlist_remove(struct ISlist *q);
#endif

