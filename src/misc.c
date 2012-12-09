#include "misc.h"
#include <stdio.h>

void PrintMac(unsigned char *mac)
{
    register int  i;

    for ( i = 0; i < 6; i++ )
    {
        if ( i !=0 )
            printf(":");
        printf("%02x", (unsigned int )mac[i]);
    }
    printf("\n");
}

void *Malloc(size_t size)
{
    void  *p;

    p = malloc(size);

    if ( p == NULL )
    {
        fprintf(stderr, "Malloc()\n");
        exit(-1);
    }

    return p;
}

