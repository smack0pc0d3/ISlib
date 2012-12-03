#ifndef INJECTOR_H
#define INJECTOR_H
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
#include "networking.h"
#include "client.h"

unsigned char		*src_mac;
unsigned char		*src_ip;
unsigned char		*router_ip;

static void (*ConstructPtr)(struct iovec *);
static struct tpacket_req packet_req;
static unsigned char *ps_hdr_start;
static int fd;

void DestructorInjector(void);
void StartInjector(char *devname, int protocol);
static void ConstructPacket(struct iovec *packet);
void GetRouterLocal(char *dev);
void SetConstructor(void (*ptr)(struct iovec *));
#endif

