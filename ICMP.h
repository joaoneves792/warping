#ifndef _WP_ICMP_H_
#define _WP_ICMP_H_

#include <pcap.h>

int receiveICMP(const struct pcap_pkthdr *header, u_char *packet, u_int16_t id, struct timeval* before);
void sendICMP(u_int32_t target, int times);

#endif
