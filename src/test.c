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
    
    return 0;
}

