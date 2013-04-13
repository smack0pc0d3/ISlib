#ifndef ARP_H
#define ARP_H

#include "../client.h"
#include "../injector.h"
#include "../sniffer.h"
#include <netinet/if_ether.h>

void AnalyzeArp(struct iovec *packet_ring, char **argv);
void GeneralArpReply(struct iovec *packet, char **argv);
void GeneralArpRequest(struct iovec *packet, char **argv);
void ClientArpPoisoning(struct iovec *packet, char **argv);
void RouterArpPoisoning(struct iovec *packet, char **argv);

#endif
