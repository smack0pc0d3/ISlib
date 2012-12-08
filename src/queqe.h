#ifndef QUEQE_H
#define QUEQE_H

#include <net/if.h> //struct iovec
#include <linux/if_packet.h> //struct tpacket_req
#include <pthread.h> //pthread_t

struct isqueqe
{
    void                (*FunctionPtr)(struct iovec *);
    struct tpacket_req  packet_req;
    unsigned char       *ps_hdr_start;
    int                 fd;
    pthread_t           id;
    struct isqueqe      *previous;
    struct isqueqe  	  *next;
};

struct isqueqe *add_queqe(struct isqueqe *q);
void delete_queqe(struct isqueqe *q);
#endif

