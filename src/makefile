#A makefile for ISlib

ARNAME = ISlib.a
AR = ar
ARFLAGS = rcs
OBJS = client.o sniffer.o list.o misc.o injector.o ISlist.o networking.o \
packet_forward.o arp.o dns.o
CC = gcc
DEBUG = -O3
CFLAGS = -c $(DEBUG)
SPATH = -I.
DFLAGS = -D_GNU_SOURCE

islib : $(OBJS)
	$(AR) $(ARFLAGS) $(ARNAME) $(OBJS)

client.o : client.c client.h networking.h misc.h
	$(CC) $(CFLAGS) client.c

sniffer.o : sniffer.c sniffer.h ISlist.h misc.h
	$(CC) $(CFLAGS) $(DFLAGS) sniffer.c

list.o : list.c list.h misc.h
	$(CC) $(CFLAGS) list.c

misc.o : misc.c misc.h
	$(CC) $(CFLAGS) misc.c
	
injector.o : injector.c injector.h client.h networking.h
	$(CC) $(CFLAGS) $(DFLAGS) injector.c
	
ISlist.o : ISlist.c ISlist.h list.h misc.h
	$(CC) $(CFLAGS) ISlist.c
	
networking.o : networking.c networking.h misc.h
	$(CC) $(CFLAGS) networking.c

packet_forward.o : packet_forward.c packet_forward.h client.h ISlist.h misc.h
	$(CC) $(CFLAGS) packet_forward.c
	
arp.o : ./protocols/arp.c ./protocols/arp.h client.h sniffer.h injector.h misc.h ISlist.h
	$(CC) $(SPATH) $(CFLAGS) ./protocols/arp.c
	
dns.o : ./protocols/dns.c ./protocols/dns.h client.h
	$(CC) $(SPATH) $(CFLAGS) ./protocols/dns.c
	
clean:
	\rm *.o

