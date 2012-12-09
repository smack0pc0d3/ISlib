#include <stdio.h>
#include "injector.h"
#include "protocols/arp.h"

int main(int argc, char *argv[])
{
    pthread_t   t;
    int         res;

    if ( argc == 1 )
    {
        fprintf(stderr, "Usage: %s interface\n", argv[0]);
        return -1;
    }
    t = InjectorInit(argv[1], ETH_P_ALL, ConstructArpRequest, sizeof(struct
                ether_arp), 20);

    if ((res = pthread_join(t, NULL)) != 0)
        perror("pthread_join");
    
    return 0;
}

