#include "packet_forward.h"
#include "client.h"
#include "ISlist.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdio.h>

void disable_pfw(void)
{
    int fd;
    char status;

    if ( (fd = open("/proc/sys/net/ipv4/ip_forward", O_RDWR)) == -1 )
    {
        perror("open():");
        exit(-1);
    }
    if ( read(fd, &status, 1) == -1 )
    {
        perror("read():");
        exit(-1);
    }

    if ( status == 1 )
    {
        status = 0;
        if ( write(fd, &status, 1) == -1 )
        {
            perror("write():");
            exit(-1);
        }
    }
    close(fd);
    disabled_default_pfw = 1;
}
 
void AnalyzePacketForward(struct iovec *packet, char **argv)
{
    struct ether_header     *ether;
    struct iphdr            *ip;
    struct client           *r, *c;
    unsigned int            net_ip;
    char                    *client_mac;
    
    if ( (r = GetRouter()) == NULL )
    {
        sleep(6);
        return;
    }

    if ( !disabled_default_pfw )
        disable_pfw();

    ether = (struct ether_header *)packet -> iov_base;
    if ( ntohs(ether -> ether_type) != ETHERTYPE_IP )
        return;

    //for somereason there are packets with null shost dhost, ignore
    if ( memcmp(ether->ether_shost,"\x00\x00\x00\x00\x00\x00", 6) == 0x00 || 
            memcmp(ether->ether_dhost, "\x00\x00\x00\x00\x00\x00",6)  == 0x00 )
        return;

    ip = (struct iphdr *)((unsigned char *)ether+sizeof(*ether));
    
    //i am an exception
    if ( memcmp((char *)src_ip, (char *)&ip->saddr, 4) == 0
            || memcmp(ether -> ether_shost, src_mac, 6) == 0 )
        return;
    net_ip = (*(unsigned int *)netmask)&(*(unsigned int *)src_ip); 
    
    //destination is in the network
    if ( net_ip == (ip -> daddr &(*(unsigned int *)netmask)) )
    {
        //if client sends to router
        if ( memcmp((char *)router_ip, (char *)&ip -> daddr, 4) == 0 )
        {
            memcpy(ether -> ether_dhost, r->mac, 6);
            memcpy(ether -> ether_shost, src_mac, 6);
        }
        //else if router/clients send to to broadcast, ignore
        else
        if ( memcmp((char *)broadcast, (char *)&ip -> daddr, 4) == 0 )
            return;
        else
        {
            if ( (client_mac = GetMacByIp(ip -> daddr)) == NULL )
                return;
            memcpy(ether -> ether_dhost, client_mac, 6);
            memcpy(ether -> ether_shost, src_mac, 6);
        }
    }
    //remote_ip
    else
    {
        if ( memcmp((char *)router_ip, (char *)&ip->saddr, 4) == 0 )
            return;
        else
            memcpy(ether -> ether_dhost, r -> mac, 6);
    }
    //lame way
    packet->iov_len = calculate_packet_len(packet);
    if ( ip -> protocol == 0x01 )
        printf("icmp\n");
    ISlist_send(packet);
}

void SendPacketForward(struct iovec *packet, char **argv)
{
    ISlist_recv(packet);
}

