#include "misc.h"
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


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

unsigned int calculate_packet_len(struct iovec *packet)
{
    struct iphdr            *ip;

    ip = (struct iphdr *)((unsigned char *)packet->iov_base+sizeof(struct ether_header));
    
    return (ntohs(ip -> tot_len)+sizeof(struct ether_header));
}


unsigned short compute_checksum(unsigned short *addr, unsigned int count) {

  register unsigned long sum = 0;

  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {

    sum += ((*addr)&htons(0xFF00));

  }

  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {

    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }

    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);

    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;
    udphdrp->check = 0;

    while (udpLen > 1) {
        sum += * ipPayload++;
        udpLen -= 2;
    }

    if(udpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}

