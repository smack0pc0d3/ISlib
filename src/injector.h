#ifndef INJECTOR_H
#define INJECTOR_H

#include <net/if.h> 
#include "queqe.h"

unsigned char *src_mac;
unsigned char *src_ip;
unsigned char *router_ip;

static struct isqueqe  *injector_queqe;
static struct isqueqe  *p;

void Injector_Init(void);
void DestructorInjector(void);
void StartInjector(char *devname, int protocol);
static void ConstructPacket(struct iovec *packet);
void GetRouterLocal(char *dev);
void SetConstructor(void (*ptr)(struct iovec *));
#endif

