#include <libnet.h>
#include <pcap.h>

extern libnet_t* l;
extern pcap_t* handle;
extern char ownIPc[];
extern char* targetc;
extern bpf_u_int32 net;
extern int host_is_up;

#define IP_HEADER_LENGHT 20
#define FILTER_EXPRESSION_ICMP "dst host %s and src host %s and icmp"
#define FILTER_LENGTH 33+(2*16)

int receiveICMP(const struct pcap_pkthdr *header, const u_char *packet, u_int16_t id, struct timeval* before){
	const struct libnet_ipv4_hdr* iphdr;
	const struct libnet_icmpv4_hdr* icmp;
	
	long rtt = ((header->ts.tv_sec - before->tv_sec)*1000L+header->ts.tv_usec/1000) - before->tv_usec/1000;
	int size_ip;

	iphdr = (struct libnet_ipv4_hdr*)(packet+LIBNET_ETH_H);
	size_ip = iphdr->ip_hl * 4;
        if (size_ip < IP_HEADER_LENGHT) {
                printf("   * Invalid IP header length: %d bytes\n", size_ip);
                return 1;
        }
	icmp = (struct libnet_icmpv4_hdr*)(packet+LIBNET_ETH_H+size_ip);

	if(ntohs(icmp->hun.echo.id) != id) //Then its not ours
		return 0;

	printf("Received %d bytes from %s rtt=%ldms seq=%hu\n", header->len, targetc, rtt, ntohs(icmp->hun.echo.seq));
	host_is_up = 1;
	return 1;
}


void sendICMP(u_int32_t target, int times, unsigned timeout){
	u_int16_t id, seq;
	int bytes_written;
	int size;
        struct bpf_program fp;          /* The compiled filter expression */
        char* filter_exp;                /* The filter expression */
	libnet_ptag_t tag = LIBNET_PTAG_INITIALIZER;
	struct pcap_pkthdr* pkthdr;
	const u_char* packet;
	int success;
	struct timeval before;

	printf("------------------Starting ICMP ECHO PING------------------\n\n");


	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);
	seq = 1;

	/*Prepare pcap to sniff our packets*/
	filter_exp = (char*)calloc(FILTER_LENGTH, sizeof(char));
	sprintf(filter_exp, FILTER_EXPRESSION_ICMP, ownIPc, targetc);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf( "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }

	/*Prepare the ICMP echo request packet*/

	if((tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq++, NULL, 0, l, tag)) == -1){
		printf("Error building ICMP header: %s\n",libnet_geterror(l));
		libnet_destroy(l);
		exit(-1);
	}

	if(libnet_autobuild_ipv4(LIBNET_IPV4_H+LIBNET_ICMPV4_ECHO_H/*+sizeof(payload)*/, IPPROTO_ICMP, target, l) == -1 ){
		printf("Error building IP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(-1);
	}

	size = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H /*+ payload*/;

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
			alarm(timeout);
			success = pcap_next_ex(handle, &pkthdr, &packet);
			alarm(0);
			if(success == 0 || success == -2){
				printf("Request timed out\n");
				break;
			}else if(success < 0){
				printf("An error ocurred while capturing a packet.\n");
				break;
			}	
		}while(!receiveICMP(pkthdr, packet, id, &before));

		if(times==1)
			break;
		if(times>0)
			times--;
        	if((tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq++, NULL, 0, l, tag)) == -1){
                	printf("Error building ICMP header: %s\n",libnet_geterror(l));
                	libnet_destroy(l);
                	exit(-1);
	        }

	}

	if(host_is_up)
		printf("------------------Host is up-----------------\n\n");
	else
		printf("---------ICMP ECHO PING INCONCLUSIVE---------\n\n");

}
