#ifndef NETWORKING_H
#define NETWORKING_H
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>

#define ERROR   -1

int CreateSocket(int family, int type, int protocol);
void BindSocket(int fd, struct sockaddr *addr, socklen_t addrlen);
int ListenSocket(int fd, int backlog);
int AcceptSocket(int fd, struct sockaddr *addr, socklen_t addrlen);
int ConnectSocket(int fd, struct sockaddr *addr, socklen_t addrlen);
ssize_t SendSocket(int fd, void *buffer, size_t len, int flags);
ssize_t RecvSocket(int fd, void *buffer, size_t len, int flags);
void DestroySocket(int fd);
struct ifreq GetFlags(int fd, char *devname);
struct ifreq SetFlags(int fd, struct ifreq oldfl, int new_flags);
struct ifreq GetIndex(int fd, char *devname);
unsigned char *GetIp(int fd, char *devname);
unsigned char *GetMac(int fd, char *devname);
void SetPromisc(int fd, struct ifreq ifr);
void RequestPacketRing(int fd, int flag, struct tpacket_req packet_req);
unsigned char *GetRouterIp(void);
in_addr_t DnsRequest(char *hostname);
#endif

