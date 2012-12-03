#ifndef CLIENT_H
#define CLIENT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct client
{
	unsigned char	ip[4];
	unsigned char	mac[6];
	struct client	*next;
};

static struct client   *c;
static struct client   *router;

void Client_Init(void);
void Client_Delete(void);
int RouterExist(void);
int ClientExist(void);
void PrintClients(void);
void PrintRouter(void);
void AddClient(unsigned char *mac, unsigned char *ip);
void AddRouter(unsigned char *mac, unsigned char *ip);
bool SearchClientMac(unsigned char *mac);
struct client *GetClient(int i);
struct client *GetRouter(void);

#endif
