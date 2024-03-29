#include "injector.h"
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


void *InjectorThread(void *void_args)
{
    struct ISlist    *iq;
    struct arguments  *args;

    args = (struct arguments *)void_args;
    pthread_mutex_lock(&m);
    iq = ISlist_add(&injector_list, args);
    pthread_mutex_unlock(&m);
    StartInjector(iq);
    StopInjector(iq);
}

pthread_t InjectorInit(char *dev, int protocol, void(*ptr)(struct
            iovec *, char **), unsigned int packet_num, char **argv, 
        pthread_t father_id)
{
    struct arguments  *args;
    
    args = (struct arguments *)Malloc(sizeof(struct arguments));
    args -> device = dev;
    args -> protocol = protocol;
    args -> FunctionPtr = ptr;
    args -> packet_num = packet_num;
    args -> argv = argv;
    args -> father_id = father_id;

    //synch not needed because only main thread is going to execute this
    if ( router_ip == NULL || src_ip == NULL )
        GetRouterLocal(dev);
    //initialize key
    if ( key_init != 1 )
    {
        key_init = 1;
        pthread_key_create(&key, NULL);
    }
    pthread_create(&args -> id, NULL, InjectorThread, (void *)args);
    return args->id;
}



void StopInjector(struct ISlist *iq)
{
    struct tpacket_stats st;
    int len = sizeof(st);

    if (!getsockopt(iq -> fd,SOL_PACKET,PACKET_STATISTICS,(char *)&st,(socklen_t *)&len))
        fprintf(stderr, "transimited %d packets dropped %d\n",
                st.tp_packets,st.tp_drops);

    if ( iq -> ps_hdr_start )
        munmap(iq -> ps_hdr_start, iq -> packet_req -> tp_block_size * iq
                -> packet_req -> tp_block_nr);

    if ( iq -> fd )
        DestroySocket(iq -> fd);

    pthread_mutex_lock(&m);
    delete_list(iq);
    pthread_mutex_unlock(&m);
    free(iq -> args);
}

//todo len+sizeof(struct tpacket_hdr) has to be equal with frame
void StartInjector(struct ISlist *iq)
{
    struct ifreq              newfl;
    struct iovec              packet_ring;
	struct tpacket_hdr        *packet_hdr;
	struct pollfd             pfd;
    register int              i;
    struct sockaddr_ll	      sock_ll;
    int                       size;
    int                       data_off, blocknum;
    
    data_off = TPACKET_HDRLEN- sizeof(struct sockaddr_ll);
    //create socket
    iq -> fd = CreateSocket(PF_PACKET, SOCK_RAW, iq -> args -> protocol);
    //get index bind socket
    newfl = GetIndex(iq -> fd, iq ->args->device);
    memset((char *)&sock_ll, '\0', sizeof(struct sockaddr_ll));
    sock_ll.sll_family = AF_PACKET;
    sock_ll.sll_protocol = htons(iq->args->protocol);
    sock_ll.sll_ifindex = newfl.ifr_ifindex;
    BindSocket(iq -> fd, (struct sockaddr *)&sock_ll, 
            sizeof(struct sockaddr_ll));
	  iq -> packet_req = CalculatePacket();
	  RequestPacketRing(iq -> fd, PACKET_TX_RING, *(iq -> packet_req));
      //map shared memory
      size = iq -> packet_req -> tp_block_size * iq -> 
          packet_req -> tp_block_nr;
      iq -> ps_hdr_start =(unsigned char *) mmap(0, size,
            PROT_READ|PROT_WRITE, MAP_SHARED, iq -> fd, 0);
      
      if ( iq -> ps_hdr_start == MAP_FAILED )
      {
          perror("mmap()");
          DestroySocket(iq -> fd);
          exit(ERROR);
      }
      //poll for our fd
      pfd.fd = iq -> fd;
      pfd.revents = 0;
      pfd.events = POLLIN|POLLRDNORM|POLLERR;
      
      i = 0;
      while (i < iq ->args->packet_num || iq->args->packet_num == 0 )
      {
          packet_hdr = (struct tpacket_hdr *)(iq -> ps_hdr_start+iq ->
                packet_req -> tp_frame_size*i);
          
          switch(packet_hdr -> tp_status)
          {
              case TP_STATUS_AVAILABLE:
                  packet_ring.iov_base = ((unsigned char *)packet_hdr+data_off);
                  iq -> args -> FunctionPtr(&packet_ring, iq -> args ->argv);
                  packet_hdr -> tp_len = packet_ring.iov_len;
                  if ( packet_hdr -> tp_len == 0 )
                      break;
                  packet_hdr->tp_status = TP_STATUS_SEND_REQUEST;
                  
                  if ( sendto(iq -> fd, NULL, 0, MSG_DONTWAIT, NULL,
                            0) == ERROR )
                  {
                      perror("send:");
                      exit(ERROR);
                  }
                  if ( iq -> args-> packet_num >= iq -> packet_req -> tp_frame_nr )
                      iq -> args -> packet_num--;
                  i = (((unsigned)i) == (unsigned)iq -> 
                          packet_req -> tp_frame_nr-1)? 0 : i+1;
                  break;
              case TP_STATUS_SENDING:
                  if ( poll(&pfd, 1, -1) < 0 )
                  {
                      perror("poll: ");
                      exit(ERROR);
                  }
                  break;
              case TP_STATUS_WRONG_FORMAT:
                  fprintf(stderr, "An error has occured during"
                        "transfer\n");
                  exit(ERROR);
        }
    }
}

void ConstructPacket(struct iovec *packet, char **argv)
{
    struct ether_header *ether;
    struct ether_arp    *arp_header;

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
    memcpy((char *)arp_header->arp_tpa, router_ip, 4);
    memset((char *)arp_header->arp_tha, '\0', 6);
    packet->iov_len = sizeof(struct ether_header)+sizeof(struct ether_arp);
}

