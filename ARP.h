#ifndef _WP_ARP_H_
#define _WP_ARP_H_

typedef struct arp_reply_hdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char sipa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tipa[4];      /* Target IP address       */ 
}arphdr_t; 

int receiveARP(const struct pcap_pkthdr *header, const u_char *packet, u_int32_t target, struct timeval* before);
void sendARP(u_int32_t target, int times);


#endif
