#ifndef ICMP_H
#define ICMP_H

#include "../client.h"
#include "../injector.h"
#include "../sniffer.h"
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>



static pthread_mutex_t cmutex;
static pthread_cond_t  cvar;
static unsigned char  *shared_packet;
/*
static int             poisonC = TRUE;

void AnalyzeIcmp(struct iovec *packet_ring);
void ConstructIcmpReply(struct iovec *packet);
void ConstructIcmpRequest(struct iovec *packet);
*/
void RedirectAnalyzePacket(struct iovec *packet_ring);
void RedirectSendPacket(struct iovec *packet_ring);
#endif
