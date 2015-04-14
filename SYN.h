#ifndef _WP_SYN_H_
#define _WP_SYN_H_


int receiveSYN(const struct pcap_pkthdr *header, const u_char *packet, struct timeval* before);
void sendSYN(u_int32_t target, int targetPort, int times);

#endif
