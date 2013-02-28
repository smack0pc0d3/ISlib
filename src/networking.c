#include "networking.h"
#include "misc.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

int CreateSocket(int family, int type, int protocol)
{
	int	fd;

	if (( fd = socket(family, type, htons(protocol)) ) == ERROR )
	{
		perror("socket:");
		exit(ERROR);
	}

	return fd;
}

struct ifreq GetFlags(int fd, char *devname)
{
	struct ifreq	ifr;

	memcpy(ifr.ifr_name, devname, IFNAMSIZ);

	if ( ioctl(fd, SIOCGIFFLAGS, &ifr) == ERROR )
	{
	    DestroySocket(fd);
		  perror("ioctl:");
		  exit(ERROR);
	}

	return ifr;
}

struct ifreq GetIndex(int fd, char *devname)
{
    struct ifreq	ifr;
    
    memcpy(ifr.ifr_name, devname, IFNAMSIZ);
    
    if ( ioctl(fd, SIOCGIFINDEX, &ifr) == ERROR)
    {
	    DestroySocket(fd);
	    perror("ioctl:");
	    exit(ERROR);
    }
    return ifr;
}

struct ifreq SetFlags(int fd, struct ifreq oldfl, int flags)
{
	struct ifreq	newfl;

	memset((char *)&newfl, '\0', sizeof(struct ifreq));
	memcpy((char *)newfl.ifr_name, (char *)oldfl.ifr_name, IFNAMSIZ);

	if ( ioctl(fd, SIOCSIFFLAGS, &newfl) == ERROR )
	{
	    DestroySocket(fd);
      perror("ioctl:");
      exit(ERROR);
	}

	newfl = oldfl;
	newfl.ifr_flags |= flags;

	if ( ioctl(fd, SIOCSIFFLAGS, &newfl) == ERROR )
  {
      DestroySocket(fd);
      perror("ioctl:");
      exit(ERROR);
  }
  
  if ( ioctl(fd, SIOCGIFINDEX, &newfl) == ERROR )
	{
	    DestroySocket(fd);
      perror("ioctl:");
      exit(ERROR);
	}

	return newfl;
}

void BindSocket(int fd, struct sockaddr *addr, socklen_t addrlen)
{
    if ( bind(fd, addr, addrlen) == ERROR )
    {
        perror("bind:");
        exit(ERROR);
    }
}

void SetPromisc(int fd, struct ifreq ifr)
{
    struct packet_mreq	mreq;
    
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    
    if ( setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == ERROR )
    {
        perror("setsockopt:");
        exit(ERROR);
    }
}

void RequestPacketRing(int fd, int request,struct tpacket_req packet_req)
{
    if ( setsockopt(fd, SOL_PACKET, request, &packet_req, sizeof(packet_req)) == ERROR )
    {
        perror("setsockopt:");
        exit(ERROR);
    }
}

void DestroySocket(int fd)
{
    if ( close(fd) == ERROR )
    {
        perror("close:");
        exit(ERROR);
    }
}
ssize_t SendSocket(int fd, void *buffer, size_t len, int flags)
{
    ssize_t     bytes;

    if (( bytes = send(fd, buffer, len, flags)) == ERROR )
    {
        perror("send");
        exit(ERROR);
    }
    return bytes;
}

ssize_t RecvSocket(int fd, void *buffer, size_t len, int flags)
{
    ssize_t     bytes;

    if (( bytes = recv(fd, buffer, len, flags)) == ERROR )
    {
        perror("send");
        exit(ERROR);
    }
    return bytes;
}

unsigned char *GetRouterIp(void)
{

	    struct nlmsghdr* nl_hdr;
    	char buf_msg[1024];
    	char* buf_msg_p;
    	int sock, recv_len, total_recv_len;
    	struct in_addr *gateway;
  
      gateway = (struct in_addr *)malloc(sizeof(struct in_addr));
    	memset( buf_msg, 0, 1024 );
    	nl_hdr = (struct nlmsghdr*) buf_msg;

    	// initialize the struct to get the route table
    	nl_hdr->nlmsg_len = NLMSG_LENGTH( sizeof(struct rtmsg) );
    	nl_hdr->nlmsg_type = RTM_GETROUTE;
    	nl_hdr->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    	nl_hdr->nlmsg_pid = getpid();

    	// open a socket for netlink
    	sock = socket( PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );

    	// send the message
    	send( sock, nl_hdr, nl_hdr->nlmsg_len, 0 );

    	buf_msg_p = buf_msg;
    	total_recv_len = 0;

    	// receive the answer
    	while ( recv_len = recv( sock, buf_msg_p, 1024 - total_recv_len, 0 ) ) 
	{
    	    struct nlmsghdr* nl_hdr_tmp = (struct nlmsghdr *) buf_msg_p;

    	    // if its done break for loop
        	if ( nl_hdr_tmp->nlmsg_type == NLMSG_DONE )
			break;
        	else 
		{
            		buf_msg_p += recv_len;
            		total_recv_len += recv_len;
        	}
    	} // end of while

    // read the saved answers and extract the default gateway
    while ( NLMSG_OK(nl_hdr, total_recv_len) ) 
    {
        struct rtmsg* rt_msg = (struct rtmsg*) NLMSG_DATA( nl_hdr );
        struct rtattr* rt_attr = (struct rtattr*) RTM_RTA( rt_msg );
        int rt_len = RTM_PAYLOAD( nl_hdr );
        in_addr_t gateway_tmp = 0, destination_tmp = 0;

        // read the route table entry's
        while( RTA_OK(rt_attr, rt_len) ) 
	{
            switch ( rt_attr->rta_type ) 
	    {
                case RTA_GATEWAY:
                    memcpy( &gateway_tmp, RTA_DATA(rt_attr), sizeof(gateway_tmp) );
                    break;
                case RTA_DST:
                    memcpy( &destination_tmp, RTA_DATA(rt_attr), sizeof(destination_tmp) );
                    break;
                default:
                    break;
            }
            // go to the next entry
            rt_attr = RTA_NEXT(rt_attr, rt_len);
        }

        // if the destination is 0.0.0.0 then its the gateway
        if ( destination_tmp == 0 ) {
            gateway->s_addr = gateway_tmp;
            break;
        }

        // go to the next answer
        nl_hdr = NLMSG_NEXT(nl_hdr, total_recv_len);
    }

    // close the socket and return the gateway
    close( sock );

    return (unsigned char *)&gateway->s_addr;
}


in_addr_t DnsRequest(char *hostname)
{
    struct hostent  *host;
    in_addr_t       ip;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror("gethostbyname:");
        exit(ERROR);
    }
    ip = inet_addr((const char *)host->h_addr_list[0]);

    return ip;
}
unsigned char *GetMac(int fd, char *device)
{
    unsigned char   *mac;
    struct ifreq    ifr;

    mac = Malloc( sizeof(unsigned char) *6);
    memcpy(ifr.ifr_name, device, 6);

    if ( ioctl(fd, SIOCGIFHWADDR, &ifr) == ERROR )
    {
        DestroySocket(fd);
        perror("ioctl:");
        exit(ERROR);
    }

    memcpy(mac, ifr.ifr_addr.sa_data, 6);

    return mac;
}

unsigned char *GetIp(int fd, char *device)
{
    unsigned char       *ip;
    struct ifreq        ifr;

    ip = Malloc(sizeof(unsigned char) *4);
    memcpy(ifr.ifr_name, device, IFNAMSIZ);

    if ( ioctl(fd, SIOCGIFADDR, &ifr) == ERROR )
    {
        DestroySocket(fd);
        perror("ioctl:");
        exit(ERROR);
    }
    memcpy(ip, (char *)&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);

    return ip;
}

