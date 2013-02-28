#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include "networking.h"
#include "client.h"
#include "queue.h"

void *SnifferThread(void *void_args)
{
    struct isqueue    *iq;
    struct arguments  *args;

    args = (struct arguments *)void_args;
    pthread_mutex_lock(&m);
    iq = add_queue(sniffer_queue);
    pthread_mutex_unlock(&m);
    SetAnalyzer(args -> FunctionPtr, iq);
    iq -> argv = args -> argv;
    StartSniffer(args -> device, args -> protocol, 
            iq, args -> packet_len, args -> packet_num); 
    StopSniffer(args, iq);

}
pthread_t SnifferInit(char *dev, int protocol, void(*ptr)(struct iovec *),
        unsigned int packet_len, unsigned int packet_num, char **argv)
{
    struct arguments  *args;
    
    args = (struct arguments *)Malloc(sizeof(struct arguments));
    args -> device = dev;
    args -> protocol = protocol;
    args -> FunctionPtr = ptr;
    args -> packet_len = packet_len;
    args -> packet_num = packet_num;
    args -> argv = argv;
    if ( router_ip == NULL || src_ip == NULL )
        GetRouterLocal(dev);
    pthread_create(&args -> thread, NULL, SnifferThread, (void *)args);

    return args->thread;
}

void StopSniffer(struct arguments *args, struct isqueue *iq)
{
    struct tpacket_stats st;
    int len = sizeof(st);

    if (!getsockopt(iq -> fd,SOL_PACKET,PACKET_STATISTICS,
                (char *)&st,(socklen_t *)&len))
        fprintf(stderr, "transimited %d packets dropped %d\n", 
                st.tp_packets,st.tp_drops);
    if ( iq -> ps_hdr_start )
        munmap(iq -> ps_hdr_start, 
                iq -> packet_req -> tp_block_size * iq -> packet_req
                -> tp_block_nr);
    if ( iq -> fd )
        DestroySocket(iq -> fd);
    pthread_mutex_lock(&m);
    delete_queue(iq);
    pthread_mutex_unlock(&m);
    free(args);
}

void StartSniffer(char *devname, int protocol, struct isqueue *iq,
        unsigned int len, unsigned int num)
{
	  struct ifreq		    newfl;
	  struct iovec        packet_ring;
	  struct tpacket_hdr  *packet_hdr;
	  struct pollfd       pfd;
	  register int        i;
	  int                 size;

	  iq -> fd = CreateSocket(PF_PACKET, SOCK_RAW, protocol);
	  newfl = GetIndex(iq -> fd, devname);
	  //promiscous mode
    SetPromisc(iq -> fd, newfl);
    //calculate packet request for packet_ring
    iq -> packet_req = CalculatePacket(len, num);
    RequestPacketRing(iq -> fd, PACKET_RX_RING, *(iq -> packet_req));
    size = iq -> packet_req -> tp_block_size * iq -> packet_req -> tp_block_nr;
    iq -> ps_hdr_start =(unsigned char *) mmap(0, size,
            PROT_READ|PROT_WRITE, MAP_SHARED, iq -> fd, 0);
    
    if ( iq -> ps_hdr_start == MAP_FAILED )
    {
        perror("mmap()");
        DestroySocket(iq -> fd);
        exit(ERROR);
    }

	  pfd.fd = iq -> fd;
    pfd.revents = 0;
    pfd.events = POLLIN|POLLRDNORM|POLLERR;
    
    i = 0; 
    while(i < num || num == 0)
	  {
        packet_hdr = (struct tpacket_hdr *)
            (iq -> ps_hdr_start+iq -> packet_req -> tp_frame_size*i);     
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
                packet_ring.iov_len = iq -> packet_req -> tp_frame_size - packet_hdr -> tp_mac;
                //AnalyzePacket(&packet_ring);
                iq -> FunctionPtr(&packet_ring);
                packet_hdr -> tp_status = TP_STATUS_KERNEL;
                if ( num >= iq -> packet_req -> tp_frame_nr )
                    num--;
                i = (((unsigned)i) == (unsigned)iq -> packet_req ->
                        tp_frame_nr-1)? 0 : i+1;
                break;
            default:
                if ( poll(&pfd, 1, -1) < 0 )
                {
                    perror("poll: ");
                    exit(ERROR);
                }
                if ( num >= iq -> packet_req -> tp_frame_nr )
                    num--;
                i = (((unsigned)i) == (unsigned)iq -> packet_req ->
                        tp_frame_nr-1)? 0 : i+1;
                break;
        }
    }
}


void AnalyzePacket(struct iovec *packet_ring)
{
    struct ether_header     *eth;
    struct ip               *iptr;
    struct  ether_arp       *arptr;

    if ( packet_ring->iov_len > sizeof(struct ether_header) )
    {
      eth = (struct ether_header *)packet_ring->iov_base;
      printf("=-=-=-=-=-=-=-=-=-=-=\n"
              "Ethernet Header\n");
      printf("source mac:");
      PrintMac(eth->ether_shost);
      printf("\ndestination mac:");
      PrintMac(eth->ether_dhost);
      printf("\n");
    }
    else
        return;

    switch(ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            iptr = (struct ip *)((unsigned char *)packet_ring->iov_base+sizeof(struct ether_header));
            printf("=-=-=-=-=-=-=-=-=-=-=\n"
                    "Ip      Header\n");
            //printf("source_addr: %s\n", inet_ntoa(iptr -> ip_src));
            //printf("destination_addr: %s\n", inet_ntoa(iptr -> ip_dst));
            break;
        case ETHERTYPE_ARP:
           arptr = (struct ether_arp *)((unsigned char *)packet_ring->iov_base+sizeof(struct ether_header));
           printf("=-=-=-=-=-=-=-=-=-=-=\n"
                   "Arp     Header\n");
           printf("sender ip: %s\n", arptr->arp_spa);
           break;
        default:
            printf("unknown\n");
            break;
    }

}

void SetAnalyzer(void(*Analyze)(struct iovec *), struct isqueue *iq)
{
    iq -> FunctionPtr = Analyze;
}

