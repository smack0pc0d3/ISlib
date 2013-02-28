#include "dns.h"

void ConstructDnsResponse(struct iovec *packet)
{
    struct ether_header   *ether;
    struct iphdr          *ip;
    struct udphdr         *udp;
    struct dnshdr         *dns;
    struct query          *query;
    unsigned char         tip[4];
    unsigned int          len;
    static unsigned char  ipq = 0;
    static unsigned short id = 1;
    struct client         *tmp;

    
    if (( tmp = GetClient((int)ipq)) == NULL )
    {
        packet -> iov_len = 0;
        ipq = 0;
        sleep(1);
        return;
    }


    tip[3] = (char)ipq;
    memcpy(tip, src_ip, 3);

    if ( memcmp(tip, src_ip, 4) == 0 )
      ipq++;

    //ethernet
    ether = (struct ether_header *)packet->iov_base;
    memcpy(ether -> ether_shost, src_mac, 6);
    memcpy(ether -> ether_dhost, router->mac, 6);
    ether -> ether_type = htons(ETHERTYPE_IP);
    //ip
    ip = (struct iphdr *)(packet->iov_base+sizeof(*ether));
    ip -> ihl = 20;
    ip -> version = 4;
    ip -> tos = 0;
    //ip -> tot_len = 0; //soon
    ip -> id = 0;
    ip -> frag_off = 0;
    ip -> ttl = 64;
    ip -> protocol = 11;//udp
    memcpy(ip -> saddr, src_ip, 4);
    memcpy(ip -> daddr, tmp -> ip, 4);
    //ip -> check = crc(ip);
    //udp
    udp = (struct udphdr
            *)(packet->iov_base+sizeof(*ether)+sizeof(*ip));
    udp -> source = htons(53); //udp port
    udp -> dest = htons(28578);
    //udp -> len = 0; //soon
    //dns 
    dns = (struct dnshdr *)(udp+sizeof(*udp));
    dns -> id = htons(0xab12);
    dns -> rd = 1;
    dns -> tc = 0;
    dns -> aa = 0;
    dns -> opcode = 0; 
    dns -> qr = 0;
    dns -> rcode = 0;
    dns -> cd = 0;
    dns -> ad = 0;
    dns -> z = 0;
    dns -> ra = 0;
    dns -> q_count = htons(1);
    dns -> ans_count = 0;
    dns -> auth_count = 0;
    dns -> add_count = 0;
    //query
    query = (struct query *)(dns+sizeof(*dns));
    
