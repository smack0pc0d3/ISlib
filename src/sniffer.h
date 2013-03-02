#ifndef SNIFFER_H
#define SNIFFER_H
#include <net/if.h> 
#include "misc.h"
#include "queue.h"
#include <pthread.h>

pthread_mutex_t         m;
static struct isqueue   *sniffer_queue = NULL;

void *SnifferThread(void *void_args);
pthread_t SnifferInit(char *dev, int protocol, void(*ptr)(struct
            iovec*, char **argv),
        unsigned int packet_len, unsigned int packet_num,
        char **argv);
void StopSniffer(struct arguments *args, struct isqueue *iq);
void StartSniffer(char *devname, int protocol, struct isqueue *iq,
                unsigned int len, unsigned int num, char **argv);
void SetAnalyzer(void(*Analyze)(struct iovec *, char **argv), struct isqueue *iq);
void AnalyzePacket(struct iovec *packet_ring, char **argv);
#endif

