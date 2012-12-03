#include "injector.h"


void DestructorInjector()
{
    struct tpacket_stats st;
    int len = sizeof(st);

    if (!getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,(char *)&st,(socklen_t *)&len))
        fprintf(stderr, "transimited %d packets dropped %d\n",
                st.tp_packets,st.tp_drops);

    if ( ps_hdr_start )
        munmap(ps_hdr_start, packet_req.tp_block_size * packet_req.tp_block_nr);

    if ( fd )
        DestroySocket(fd);
}

void StartInjector(char *devname, int protocol)
{
    struct ifreq		    newfl;
    struct iovec        packet_ring;
	  struct tpacket_hdr  *packet_hdr;
	  struct pollfd       pfd;
	  register int        i;
	  struct sockaddr_ll	sock_ll;
	  int                 size;
	  int                 data_off;

    data_off = TPACKET_HDRLEN- sizeof(struct sockaddr_ll);
    fd = CreateSocket(PF_PACKET, SOCK_RAW, protocol);
	  newfl = GetIndex(fd, devname);
	  memset((char *)&sock_ll, '\0', sizeof(struct sockaddr_ll));
	  sock_ll.sll_family = AF_PACKET;
	  sock_ll.sll_protocol = htons(protocol);
	  sock_ll.sll_ifindex = newfl.ifr_ifindex;
	  BindSocket(fd, (struct sockaddr *)&sock_ll, sizeof(struct sockaddr_ll));
    packet_req.tp_block_size = 4096;
	  packet_req.tp_frame_size = 1024;
	  packet_req.tp_block_nr = 64;
	  packet_req.tp_frame_nr = 4*64;
	  RequestPacketRing(fd, PACKET_TX_RING, packet_req);
    size = packet_req.tp_block_size * packet_req.tp_block_nr;
    ps_hdr_start =(unsigned char *) mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    
    if ( ps_hdr_start == MAP_FAILED )
    {
        perror("mmap()");
        DestroySocket(fd);
        exit(ERROR);
    }
    pfd.fd = fd;
    pfd.revents = 0;
    pfd.events = POLLIN|POLLRDNORM|POLLERR;

    for (i = 0; ; )
    {
        packet_hdr = (struct tpacket_hdr *)(ps_hdr_start+packet_req.tp_frame_size*i);

        switch(packet_hdr -> tp_status)
        {
            case TP_STATUS_AVAILABLE:
                packet_ring.iov_base = ((unsigned char *)packet_hdr+data_off);
                ConstructPtr(&packet_ring);
                packet_hdr -> tp_len = packet_ring.iov_len;
                if ( packet_hdr -> tp_len == 0 )
                    break;
                packet_hdr->tp_status = TP_STATUS_SEND_REQUEST;
                if ( sendto(fd,
                            NULL,
				                    0,
                            MSG_DONTWAIT,
                            NULL,
                            0) == ERROR )
                {
                    perror("send:");
                    exit(ERROR);
                }
                break;
            case TP_STATUS_SENDING:
                if ( poll(&pfd, 1, -1) < 0 )
                {
                    perror("poll: ");
                    exit(ERROR);
                }
                i = (((unsigned)i) == (unsigned)packet_req.tp_frame_nr)? 0 : i+1;
                break;
            case TP_STATUS_WRONG_FORMAT:
                fprintf(stderr, "An error has occured during"
                        "transfer");
                exit(ERROR);
            default:
                if ( poll(&pfd, 1, -1) < 0 )
                {
                    perror("poll: ");
                    exit(ERROR);
                }
                i = (((unsigned)i) == (unsigned)packet_req.tp_frame_nr)? 0 : i+1;
                break;
        }
    }
}

void ConstructPacket(struct iovec *packet)
{
    struct ether_header *ether;
    struct ether_arp    *arp_header;

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
    memcpy((char *)arp_header->arp_spa, (char *)src_ip, 4);
    memcpy((char *)arp_header->arp_tpa, router_ip, 4);
    memset((char *)arp_header->arp_tha, '\0', 6);
    packet->iov_len = sizeof(struct ether_header)+sizeof(struct ether_arp);
}

void GetRouterLocal(char *dev)
{
    struct ifreq    ifr;
    int             fd;

    fd = CreateSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    memcpy(ifr.ifr_name, dev, IFNAMSIZ);
    src_mac = GetMac(fd, dev);
    src_ip = GetIp(fd, dev);
    router_ip = GetRouterIp();
}

void SetConstructor(void (*ptr)(struct iovec *))
{
    ConstructPtr = ptr;
}

