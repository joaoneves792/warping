#ifndef _WP_ACK_H_
#define _WP_ACK_H_


int receiveACK(const struct pcap_pkthdr *header, const u_char *packet, struct timeval* before);
void sendACK(u_int32_t target, int targetPort, int times);

#endif
