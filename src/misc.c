#include "misc.h"

void Print_Mac(unsigned char *mac)
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
    void  *tmp;

    tmp = malloc(size);

    if ( tmp == NULL )
    {
        fprintf(stderr, "Error: Malloc()");
        exit(-1);
    }
    return tmp;
}

