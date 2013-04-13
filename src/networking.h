#ifndef NETWORKING_H
#define NETWORKING_H

#include <netdb.h>
#include <linux/if_packet.h>
#include <net/if.h> 
 
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
unsigned char *GetNetmask(int fd, char *devname);
unsigned char *GetBroadcast(int fd, char *device);
void SetPromisc(int fd, struct ifreq ifr);
void RequestPacketRing(int fd, int flag, struct tpacket_req packet_req);
unsigned char *GetRouterIp(void);
in_addr_t DnsRequest(char *hostname);
#endif

