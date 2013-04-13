#ifndef PACKET_FORWARD_H
#define PACKET_FORWARD_H
#include "injector.h"
#include "sniffer.h"

static int disabled_default_pfw = 0;
void SendPacketForward(struct iovec *packet, char **argv);
void AnalyzePacketForward(struct iovec *packet, char **argv);
void disable_pfw(void);
#endif
