#ifndef DNS_H
#define DNS_H
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

struct dnshdr
{
    unsigned short id;
    /*
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
    */
    unsigned short flags;
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} __attribute__ ((__packed__));

struct question
{
    unsigned short qtype;
    unsigned short qclass;
} __attribute__ ((__packed__));

struct query
{
    unsigned char *name;
    struct question quest;
} __attribute__ ((__packed__));

struct rdata
{
    unsigned short type;
    unsigned short _class;
    unsigned int   ttl;
    unsigned short data_len;
} __attribute__ ((__packed__));

struct res_record
{
    unsigned short name;
    struct rdata resources;
    unsigned int rdata;
} __attribute__ ((__packed__));

void AnalyzeDns(struct iovec *packet, char **argv);
void DnsResponse(struct iovec *packet, char **argv);
#endif

