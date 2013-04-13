#ifndef INJECTOR_H
#define INJECTOR_H

#include <net/if.h> 
#include "misc.h"
#include "ISlist.h"
#include <pthread.h>


pthread_mutex_t m;

//extern pthread_key_t  key;
struct ISlist   *injector_list;

pthread_t InjectorInit(char *dev, int protocol, void (*ptr)(struct
        iovec *, char **), unsigned int packet_len, 
        char **argv, pthread_t father_id);
void *InjectorThread(void *void_args);
void StopInjector(struct ISlist *iq);
void StartInjector(struct ISlist *iq);
static void ConstructPacket(struct iovec *packet, char **argv);
//void SetConstructor(void (*ptr)(struct iovec *, char **argv), struct ISlist *iq);
#endif

