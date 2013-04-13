#include <stdio.h>
#include <stdlib.h>
#include "injector.h"
#include "sniffer.h"
#include "protocols/arp.h"

int main(int argc, char *argv[])
{
    register int  i;
    pthread_t   t[2];
    int         res;

    if ( argc == 1 )
    {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return -1;
    }
    t[0] = SnifferInit(argv[1], ETH_P_ARP, AnalyzeArp, -1, NULL, -1);
    t[1] = InjectorInit(argv[1], ETH_P_ARP, GeneralArpRequest, -1,
            NULL, -1);
    
    for ( i = 0; i < 2; i++ )
    {
        pthread_join(t[i], NULL);
    }
    return 0;
}

