#ifndef CLIENT_H
#define CLIENT_H

#define FALSE 0
#define TRUE  1

struct client
{
	unsigned char	ip[4];
	unsigned char	mac[6];
	struct client	*next;
};

unsigned char *src_mac;
unsigned char *src_ip;
unsigned char *router_ip;
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
int SearchClientMac(unsigned char *mac);
struct client *GetClient(int i);
struct client *GetRouter(void);
void GetRouterLocal(char *dev);

#endif

