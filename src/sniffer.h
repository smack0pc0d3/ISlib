#ifndef SNIFFER_H
#define SNIFFER_H
#include <net/if.h> 
#include "misc.h"
#include "ISlist.h"
#include <pthread.h>

pthread_mutex_t         m;
struct ISlist   *sniffer_list;

void *SnifferThread(void *void_args);
pthread_t SnifferInit(char *dev, int protocol, void(*ptr)(struct
            iovec*, char **),
        unsigned int packet_num,
        char **argv, pthread_t father_id);
void StopSniffer(struct ISlist *iq);
void StartSniffer(struct ISlist *iq);
//void SetAnalyzer(void(*Analyze)(struct iovec *, char **argv), struct ISlist *iq);
void AnalyzePacket(struct iovec *packet_ring, char **argv);
#endif

