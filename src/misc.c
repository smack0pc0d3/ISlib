#include "misc.h"
#include <stdio.h>

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

struct tpacket_req *CalculatePacket(unsigned int len, unsigned int num)
{
    struct tpacket_req  *p = Malloc(sizeof(struct tpacket_req));
  
    p -> tp_frame_nr = 8;
    p -> tp_frame_size = 2048;
    p -> tp_block_size = 4096;
    p -> tp_block_nr = 4;

    return p;
}

unsigned int power(unsigned int len)
{
    register int i;
    unsigned int p = 2;

    for ( i = 0; i < len; i++)
    {
        p *= p;
    }
    return len;
}

