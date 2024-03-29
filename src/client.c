#include "client.h"
#include "networking.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "misc.h"

void Client_Init(void)
{
    //initialize c struct
    c = NULL;
    router = NULL;
}

int SearchClientMac(unsigned char *mac)
{
    struct client   *tmp;
    int            found = FALSE;

    if( ClientExist() == -1 )
        return FALSE;
    tmp = c;

    do
    {
        if ( memcmp(mac, tmp -> mac, 6) == 0 )
        {
            found = TRUE;
            break;
        }
        tmp = tmp -> next;
    }
    while ( tmp != (struct client *)NULL );

    return found;
}

void AddClient(unsigned char *mac, unsigned char *ip)
{
    struct client   *tmp;

    if ( c == NULL )
    {
        c = Malloc(sizeof(struct client));
        tmp = c;
        tmp -> next = NULL;
        memcpy((unsigned char *)tmp -> mac, (unsigned char *)mac, 6);
        memcpy((unsigned char *)tmp -> ip, (unsigned char *)ip, 4);
        return;
    }

    tmp = c;
    while ( tmp->next != NULL)
    {
        tmp = tmp -> next;
    }
    tmp -> next = Malloc(sizeof(struct client));
    tmp = tmp -> next;
    tmp -> next = NULL;
    memcpy((unsigned char *)tmp -> mac, (unsigned char *)mac, 6);
    memcpy((unsigned char *)tmp -> ip, (unsigned char *)ip, 4);
}

struct client *GetClient(int i)
{
    struct client   *tmp;
    register int    j = 0;

    if( ClientExist() == -1 )
        return NULL;
    tmp = c;

    while (tmp -> next != NULL && j < i)
    {
        tmp = tmp -> next;
        j++;
    }
    if ( j < i)
        return NULL;

    return tmp;
}
char *GetMacByIp(unsigned int ip)
{
    struct client   *c;
    register int    i = 0;

    while ( (c = GetClient(i)) != NULL )
    {
        if ( memcmp((char *)&c-> ip, (char *)&ip, 4) == 0 )
            break;
        i++;
    }

    if ( c == NULL )
        return NULL;

    return c -> mac;
}

void DeleteClient(void)
{
    struct client *tmp;

    if( ClientExist() == -1 )
        return;

    tmp = c;

    do
    {
        c = c -> next;
        free(tmp);
        tmp = c;
    }
    while( tmp != (struct client *)NULL );
}

void PrintClients()
{
    struct client   *tmp;
    register int    i = 0;

    if( ClientExist() == -1 )
        return;
    printf("_____________________________________________________\n");
    tmp = c;
    printf("=-=-=-=-=Clients=-=-=-=-=\n");
    do
    {
        printf("client mac [%d] = ", i);
        PrintMac(tmp->mac);
        printf("client ip [%d] = ", i);
        PrintIp(tmp->ip);
        tmp = tmp -> next;
        i++;
    }while (tmp != (struct client *)NULL);
    printf("=-=-=-=-=-=-=-=-=-=-=-=-=\n\n");
}

int RouterExist(void)
{
    if (router == NULL )
        return -1;

    return 0;
}

void AddRouter(unsigned char *mac, unsigned char *ip)
{
    router = Malloc(sizeof(struct client));
    memcpy((char *)router->mac, (char *)mac, 6);
    memcpy((char *)router->ip, (char *)ip, 4);
}

int ClientExist(void)
{
    if ( c == NULL )
        return -1;

    return 0;
}

struct client *GetRouter(void)
{
    if ( RouterExist() == -1)
        return NULL;
    return router;
}

void PrintRouter(void)
{

    if( RouterExist() == -1 )
        return;

    printf("=-=-=-=-=Router=-=-=-=-=\n");
    printf("Router mac = ");
    PrintMac(router->mac);
    printf("Router ip = ");
    PrintIp(router->ip);
    printf("=-=-=-=-=-=-=-=-=-=-=-=-=\n\n");
    printf("_____________________________________________________\n");
}

void Client_Destroy(void)
{
    DeleteClient();
    free(router);
    free(src_ip);
    free(src_mac);

    if ( netmask )
        free(netmask);

}

void GetRouterLocal(char *dev)
{
    struct ifreq    ifr;
    int             fd;

    fd = CreateSocket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    memcpy(ifr.ifr_name, dev, IFNAMSIZ);
    src_mac = GetMac(fd, dev);
    src_ip = GetIp(fd, dev);
    netmask = GetNetmask(fd, dev);
    router_ip = GetRouterIp();
    broadcast = GetBroadcast(fd, dev);
}

