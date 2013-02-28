#ifndef INJECTOR_H
#define INJECTOR_H

#include <net/if.h> 
#include "misc.h"
#include "queue.h"
#include <pthread.h>


pthread_mutex_t m;


static struct isqueue   *injector_queue = NULL;

pthread_t InjectorInit(char *dev, int protocol, void (*ptr)(struct iovec *),
        unsigned int packet_len, unsigned int packet_num, char **argv);
void *InjectorThread(void *void_args);
void StopInjector(struct arguments *args, struct isqueue *iq);
void StartInjector(char *devname, int protocol, struct isqueue *iq,
        unsigned int len, unsigned int num);
static void ConstructPacket(struct iovec *packet);
void SetConstructor(void (*ptr)(struct iovec *), struct isqueue *iq);
#endif

