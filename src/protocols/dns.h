#ifndef DNS_H
#define DNS_H
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

struct dnshdr
{
    unsigned short id;
    unsigned char rd:1;
    unsigned char tc:1;
    unsigned char aa:1;
    unsigned char opcode:4;
    unsigned char qr:1;
    unsigned char rcode:1;
    unsigned char cd:1;
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct question
{
    unsigned short qtype;
    unsigned short qclass;
};

struct query
{
    unsigned char *name;
    struct question quest;
};

struct rdata
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

struct res_record
{
    unsigned char *name;
    struct rdata *resources;
    unsigned char *rdata;
};

void ConstructDnsResponse(struct iovec *packet, char **argv);
#endif

