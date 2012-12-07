#ifndef ARP_H
#define ARP_H

#include "../client.h"
#include "../injector.h"
#include "../sniffer.h"

static pthread_mutex_t cmutex;
static int             poisonC;

void AnalyzeArp(struct iovec packet_ring);
static void ConstructArpReply(struct iovec *packet);
static void ConstructArpRequest(struct iovec *packet);

#endif
