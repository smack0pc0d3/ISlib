#include "dns.h"

void ConstructDnsResponse(struct iovec *packet, char **argv)
{
    struct ether_header   *ether;
    struct iphdr          *ip;
    struct udphdr         *udp;
    struct dnshdr         *dns;
    struct query          *query;
    struct res_record     *answer;
    static int            client_index = 0;
    static int            domain_index = 0;
    unsigned int          len;
    static unsigned short id = 1;
    struct client         *tmp;

    
    if (( tmp = GetClient(client_index)) == NULL )
    {
        packet -> iov_len = 0;
        client_index = 0;
        sleep(1);
        return;
    }
    if ( argv == NULL )
    {
        fprintf(stderr, "Error calling construct dns response without
                domains in arguments");
        return;
    }

    if ( argv[domain_index] == NULL )
    {
        packet -> iov_len = 0;
        domain_index = 0;
        sleep(1);
        return;
    }
    
    //ethernet
    ether = (struct ether_header *)packet->iov_base;
    memcpy(ether -> ether_shost, src_mac, 6);
    memcpy(ether -> ether_dhost, tmp -> mac, 6);
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
    memcpy(ip -> saddr, router_ip, 4);
    memcpy(ip -> daddr, tmp -> ip, 4);
    //ip -> check = crc(ip);
    //udp
    udp = (struct udphdr
            *)(packet->iov_base+sizeof(*ether)+sizeof(*ip));
    udp -> source = htons(53); //udp port
    udp -> dest = htons(28578); //depends on request
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
    dns -> ra = 1;
    dns -> q_count = htons(1);
    dns -> ans_count = htons(1);
    dns -> auth_count = 0;
    dns -> add_count = 0;
    //query question
    query = (struct query *)(dns+sizeof(*dns));
    memcpy(query -> name, argv[i], (strlen(argv[domain_index]) <
                256)?strlen(argv[domain_index]):256);
    query -> quest.qtype = htons(1);//depends on req
    query -> quest.qclass = (1); // depends on req
    //res_record answer 
    answer = (struct res_record *)(query+sizeof(*query));
    memcpy(answer -> name, argv[domain_index],
            (strlen(argv[domain_index])<256)?strlen(argv[domain_index]):256);
    answer -> resources -> type = htons(1);//dpends on req
    answer -> resources -> _class = htons(1);//depends on req
    answer -> resources -> ttl = htonl(0x00015180);
    answer -> resources -> data_len = htons(4);
    memcpy(answer -> resources -> rdata, "1921", 4);

