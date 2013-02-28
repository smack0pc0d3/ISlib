#include <stdio.h>
#include <stdlib.h>
#include "injector.h"
#include "sniffer.h"
#include "protocols/arp.h"

int main(int argc, char *argv[])
{
    register int  i;
    pthread_t   t[3];
    int         res;

    if ( argc == 1 )
    {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return -1;
    }
    
    //arp request
    t[0] = InjectorInit(argv[1], ETH_P_ARP, ConstructArpRequest, sizeof(struct
                ether_arp), 0, NULL);

    //analyze arp
    t[1] = SnifferInit(argv[1], ETH_P_ARP, AnalyzeArp, sizeof(struct
                ether_arp), 0, NULL);
    
    //send arp reply
    t[2] = InjectorInit(argv[1], ETH_P_ARP, ConstructArpReply,
            sizeof(struct ether_arp), 0, NULL);

    for ( i = 0; i < 3; i++ )
    {
        if ((res = pthread_join(t[i], NULL)) != 0)
            perror("pthread_join");
    }
    
    return 0;
}

