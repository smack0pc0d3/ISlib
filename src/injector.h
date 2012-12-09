#ifndef INJECTOR_H
#define INJECTOR_H

#include <net/if.h> 
#include "misc.h"
#include "queqe.h"
#include <pthread.h>

struct arguments
{
    char  *device;
    int   protocol;
    void  (*FunctionPtr)(struct iovec *);
    pthread_t  thread;
    unsigned int  packet_len;
    unsigned int  packet_num;
};

pthread_mutex_t m;

unsigned char *src_mac;
unsigned char *src_ip;
unsigned char *router_ip;

static struct isqueqe   *injector_queqe = NULL;

pthread_t InjectorInit(char *dev, int protocol, void (*ptr)(struct iovec
            *), unsigned int packet_len, unsigned int packet_num);
void *InjectorThread(void *void_args);
void StopInjector(struct arguments *args, struct isqueqe *iq);
void StartInjector(char *devname, int protocol, struct isqueqe *iq,
        unsigned int len, unsigned int num);
static void ConstructPacket(struct iovec *packet);
void GetRouterLocal(char *dev);
void SetConstructor(void (*ptr)(struct iovec *), struct isqueqe *iq);
#endif

