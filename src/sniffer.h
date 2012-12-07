#ifndef SNIFFER_H
#define SNIFFER_H
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

void SetAnalyzer(void(*Analyze)(struct iovec ));
void DestructorSniffer(void);
void StartSniffer(char *devname, int protocol);
void AnalyzePacket(struct iovec packet_ring);
#endif

