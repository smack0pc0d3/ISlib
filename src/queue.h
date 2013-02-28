#ifndef QUEQE_H
#define QUEQE_H

#include <net/if.h> //struct iovec
#include <linux/if_packet.h> //struct tpacket_req
#include <pthread.h> //pthread_t

struct isqueue
{
    void                (*FunctionPtr)(struct iovec *); 
    struct tpacket_req  *packet_req; //request space for mmap
    unsigned char       *ps_hdr_start; //available space for packet
    int                 fd;
    pthread_t           id; 
    struct isqueue      *previous;
    struct isqueue  	  *next;
};

struct isqueue *add_queue(struct isqueue *q);
void delete_queue(struct isqueue *q);
#endif

