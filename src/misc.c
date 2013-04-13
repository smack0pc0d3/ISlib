#include "misc.h"
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

void PrintMac(unsigned char *mac)
{
    register int  i;

    for ( i = 0; i < 6; i++ )
    {
        if ( i !=0 )
            printf(":");
        printf("%02x", (unsigned int )mac[i]);
    }
    printf("\n");
}
void PrintIp(unsigned char *ip)
{
    register int  i;

    for ( i = 0; i < 4; i++ )
    {
        if ( i != 0 )
            printf(".");
        printf("%d", (int )ip[i]);
    }
    printf("\n");
}

void *Malloc(size_t size)
{
    void  *p;

    p = malloc(size);

    if ( p == NULL )
    {
        fprintf(stderr, "Malloc()\n");
        exit(-1);
    }

    return p;
}

struct tpacket_req *CalculatePacket(void)
{
    struct tpacket_req  *p = Malloc(sizeof(struct tpacket_req));
  
    p -> tp_frame_nr = 8;
    p -> tp_frame_size = 2048;
    p -> tp_block_size = 4096;
    p -> tp_block_nr = 4;

    return p;
}

unsigned int checksum(unsigned char *buf, unsigned nbytes, unsigned
        int sum)
{
	int i;

	for (i = 0; i < (nbytes & ~1U); i += 2)
	{
		sum += (unsigned short)ntohs(*((unsigned short *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	if (i < nbytes)
	{
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return (sum);
}

unsigned int wrapsum(unsigned int sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

unsigned int calculate_packet_len(struct iovec *packet)
{
    struct iphdr            *ip;

    ip = (struct iphdr *)((unsigned char *)packet->iov_base+sizeof(struct ether_header));
    
    return (ntohs(ip -> tot_len)+sizeof(struct ether_header));
}


