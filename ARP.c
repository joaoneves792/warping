#include <pcap.h>
#include <libnet.h>

#include "ARP.h"

extern libnet_t* l;
extern char libneterrbuf[];
extern pcap_t* handle;
extern u_int32_t ownIP;
extern char* targetc;
extern bpf_u_int32 net;
extern int host_is_up;
extern char* dev;

int receiveARP(const struct pcap_pkthdr *header, const u_char *packet, u_int32_t target, struct timeval* before){
	const struct arp_reply_hdr* arp;
	long rtt = ((header->ts.tv_sec - before->tv_sec)*1000L+header->ts.tv_usec/1000) - before->tv_usec/1000;
	char tmp[16];

	if(header->len < LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H)
		return 0;
	arp = (struct arp_reply_hdr*)(packet+LIBNET_ETH_H);
	
	/*Check if its a reply from our target*/
	if(ntohs(arp->oper) != ARPOP_REPLY)
		return 0;
	sprintf(tmp, "%hu.%hu.%hu.%hu", arp->sipa[0], arp->sipa[1], arp->sipa[2], arp->sipa[3]);
	if(strcmp(tmp, targetc))
		return 0;
	
	printf("Received %d bytes from %s rtt=%ldms\n", header->len, targetc, rtt);
	host_is_up = 1;
	return 1;
}


void sendARP(u_int32_t target, int times){
	struct libnet_ether_addr *src_mac_addr;
	char src_mac_char[18];
	u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct bpf_program fp;          /* The compiled filter expression */
        char* filter_exp;                /* The filter expression */
	int bytes_written;
        struct pcap_pkthdr* pkthdr;
        const u_char* packet;
        int success;

	struct timeval before;
	int size;

        printf("------------------Starting ARP PING------------------\n\n");

	/*We need to use the link layer so we have to change into link mode*/
	if(l)
		libnet_destroy(l);
        l = libnet_init(LIBNET_LINK, dev, libneterrbuf);
        if ( l == NULL ) {
                printf("libnet_init() failed: %s\n", libneterrbuf);
                exit(-1);
        }
	/*Get our MAC address*/
	src_mac_addr = libnet_get_hwaddr(l);
	if(src_mac_addr == NULL ) {
		printf("Couldn't get own MAC address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(-1);
	}
	/*Prepare pcap to sniff our packets*/
        filter_exp = (char*)calloc(33+(2*16), sizeof(char));
	sprintf(src_mac_char, "%02x:%02x:%02x:%02x:%02x:%02x", src_mac_addr->ether_addr_octet[0], src_mac_addr->ether_addr_octet[1], src_mac_addr->ether_addr_octet[2], src_mac_addr->ether_addr_octet[3], src_mac_addr->ether_addr_octet[4], src_mac_addr->ether_addr_octet[5]);
        sprintf(filter_exp, "ether dst host %s and arp", src_mac_char);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf( "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }
	


	if(libnet_autobuild_arp(ARPOP_REQUEST, src_mac_addr->ether_addr_octet, (u_int8_t*)(&ownIP), mac_zero_addr, (u_int8_t*)(&target), l) == -1){
		printf("Error building ARP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(-1);
	}
	if(libnet_autobuild_ethernet(mac_broadcast_addr, ETHERTYPE_ARP, l) == -1){
		printf("Error building Ethernet header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(-1);
	}

	size = LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H;

        /*Send the packets*/
        if(times > 0)
                printf("Sending %d x %d bytes...\n", times, size);
        else
                printf("Sending %d bytes in an infinite cycle...\n", size);
        while(times){
                gettimeofday(&before, NULL);
                bytes_written = libnet_write(l);
                if(bytes_written == -1){
                        printf("Error writing packet: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(-1);
                }

                /*Capture the reply to the packet we just sent*/
                do{
                        success = pcap_next_ex(handle, &pkthdr, &packet);
                        if(success == 0){
                                printf("Request timed out\n");
                                break;
                        }else if(success < 0){
                                printf("An error ocurred while capturing a packet.\n");
                                break;
                        }
                }while(!receiveARP(pkthdr, packet, target, &before));
		

                if(times==1)
                        break;
                if(times>0)
			times--;
	}

	libnet_destroy(l);
        l = libnet_init(LIBNET_RAW4, dev, libneterrbuf);
        if ( l == NULL ) {
                printf("libnet_init() failed: %s\n", libneterrbuf);
                exit(-1);
        }
        if(host_is_up)
                printf("------------------Host is up-----------------\n\n");
        else
                printf("------------------Host is down---------------\n\n");

}
