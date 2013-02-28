#ifndef MISC_H
#define MISC_H
#include <stdlib.h>
#include <net/if.h> 
#include <pthread.h>
#include <linux/if_packet.h>


struct arguments
{
    char          *device;
    int           protocol;
    void          (*FunctionPtr)(struct iovec *);
    pthread_t     thread;
    char          **argv;
    unsigned int  packet_len;
    unsigned int  packet_num;
};


void *Malloc(size_t size);
void PrintMac(unsigned char *mac);
void PrintIp(unsigned char *ip);
struct tpacket_req *CalculatePacket(unsigned int len, unsigned int
        num);
unsigned int power(unsigned int len);
#endif
