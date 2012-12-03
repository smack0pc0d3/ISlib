#include "sniffer.h"
#include "networking.h"
#include "client.h"
#include "misc.h"

void DestructorSniffer(void)
{
	struct tpacket_stats st;
	int len = sizeof(st);

	if (!getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,(char *)&st,(socklen_t *)&len))
      fprintf("recieved %d packets, dropped %d packets"
              ,st.tp_packets, st.tp_drops);

    if ( ps_hdr_start )
        munmap(ps_hdr_start, packet_req.tp_block_size * packet_req.tp_block_nr);

    if ( fd )
        DestroySocket(fd);
}

void StartSniffer(char *devname, int protocol)
{
	  struct ifreq		newfl;
	  struct iovec        packet_ring;
	  struct tpacket_hdr  *packet_hdr;
	  struct pollfd       pfd;
	  register int        i;
	  int                 size;


	  fd = CreateSocket(PF_PACKET, SOCK_RAW, protocol);
	  newfl = GetIndex(fd, devname);
	  SetPromisc(fd, newfl);
    packet_req.tp_block_size = 4096;
	  packet_req.tp_frame_size = 1024;
	  packet_req.tp_block_nr = 64;
	  packet_req.tp_frame_nr = 4*64;
	  RequestPacketRing(fd, PACKET_RX_RING, packet_req);
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
    
    for ( i = 0; ; )
	  {
        packet_hdr = (struct tpacket_hdr *)(ps_hdr_start+packet_req.tp_frame_size*i);
        
        switch(packet_hdr -> tp_status)
        {
            case TP_STATUS_KERNEL:
                if ( poll(&pfd, 1, -1) < 0 )
                {
                    perror("poll: ");
                    exit(ERROR);
                }
                break;
            case TP_STATUS_USER:
			      case 5:
			      case 9:
                packet_ring.iov_base = ((unsigned char *)packet_hdr+packet_hdr -> tp_mac);
                packet_ring.iov_len = packet_req.tp_frame_size - packet_hdr -> tp_mac;
                AnalyzePacket(packet_ring);
                packet_hdr -> tp_status = TP_STATUS_KERNEL;
                i = (((unsigned)i) == (unsigned)packet_req.tp_frame_nr)? 0 : i+1;
                break;
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

void AnalyzePacket(struct iovec packet_ring)
{
    struct ether_header     *eth;
    struct ip               *iptr;
    struct  ether_arp       *arptr;
    Misc		            m;

    eth = (ether_header *)packet_ring.iov_base;
    cout << "=-=-=-=-=-=-=-=-=-=-=\n"
         << "Ethernet Header" << endl;
    cout << "source mac:";
    m.PrintMac(eth->ether_shost);
    cout << endl;
    cout << "destination mac:";
    m.PrintMac(eth->ether_dhost);
    cout << endl;

    switch(ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            iptr = (struct ip *)((unsigned char *)packet_ring.iov_base+sizeof(struct ether_header));
            cout << "=-=-=-=-=-=-=-=-=-=-=\n"
                 << "Ip      Header" << endl;
            cout << "source_addr:" << inet_ntoa(iptr -> ip_src) << endl;
            cout << "destination_addr:" << inet_ntoa(iptr -> ip_dst) << endl;
            break;
        case ETHERTYPE_ARP:
           arptr = (struct ether_arp *)((unsigned char *)packet_ring.iov_base+sizeof(struct ether_header));
           cout << "=-=-=-=-=-=-=-=-=-=-=\n"
                 << "Arp     Header" << endl;
           cout << "sender ip:" << arptr->arp_spa << endl;
           break;
        default:
            cout << "unknown" << endl;
            break;
    }

}

void SetAnalyzer(void(*Analyze)(struct iovec ))
{
    Analyzer = Analyze;
}


