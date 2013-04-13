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
    void          (*FunctionPtr)(struct iovec *, char **argv);
    pthread_t     father_id;
    pthread_t     id;
    char          **argv;
    unsigned int  packet_num;
};

void *Malloc(size_t size);
void PrintMac(unsigned char *mac);
void PrintIp(unsigned char *ip);
struct tpacket_req *CalculatePacket(void);
unsigned int checksum(unsigned char *buf, unsigned nbytes, unsigned
        int sum);
unsigned int wrapsum(unsigned int sum);
unsigned int calculate_packet_len(struct iovec *packet);
#endif
