#ifndef ARP_H
#define ARP_H

#include "../client.h"
#include "../injector.h"
#include "../sniffer.h"
#include <netinet/if_ether.h>

static pthread_mutex_t cmutex;
static pthread_cond_t  cvar;
static int             poisonC = TRUE;

void AnalyzeArp(struct iovec *packet_ring);
void ConstructArpReply(struct iovec *packet);
void ConstructArpRequest(struct iovec *packet);

#endif
