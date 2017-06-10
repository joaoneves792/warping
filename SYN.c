#include <pcap.h>
#include <libnet.h>

#include "SYN.h"

extern libnet_t* l;
extern pcap_t* handle;
extern char* targetc;
extern bpf_u_int32 net;
extern int host_is_up;
extern char ownIPc[];
u_int32_t targetIP;
int port;

#define SOURCE_PORT 65000
#define FILTER_EXPRESSION_SYN "dst host %s and src host %s and tcp and dst port 65000"
#define FILTER_LENGTH 51+(2*16)

void closeSession(){
        libnet_ptag_t tag = LIBNET_PTAG_INITIALIZER;
	int bytes_written;

	tag = libnet_build_tcp(SOURCE_PORT,     // Source TCP port 
                port,    			// Destination TCP port 
                htonl(1),			// Sequence number 
                ntohl(1),			// Acknowledgement number (SYN's seq # + 1)
                TH_ACK,				// Control flags (SYN flag set only)
                libnet_get_prand(LIBNET_PRu16), // Window size (randomized)
                0,                              // Checksum (0 to autofill)
                0,                              // Urgent pointer
                LIBNET_TCP_H,                   // Length of the TCP packet (no data means only the header size)
                NULL,                           // Payload (none)
                0,                              // Payload length
                l, tag);                 	// Context and tag for this packet

	if(tag < 0){
	printf("Error building TCP header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(-1);
        }

	if(libnet_autobuild_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H, IPPROTO_TCP, targetIP, l) == -1 ){
                printf("Error building IP header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(-1);
        }

        bytes_written = libnet_write(l);//Send the ACK
	if(bytes_written == -1){
                        printf("Error writing packet: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(-1);
        }

	tag = libnet_build_tcp(SOURCE_PORT,	// Source TCP port 
                port,    			// Destination TCP port 
                htonl(1),			// Sequence number 
                ntohl(1),			// Acknowledgement number (SYN's seq # + 1)
                TH_ACK | TH_RST,		// Control flags (SYN flag set only)
                libnet_get_prand(LIBNET_PRu16), // Window size (randomized)
                0,                              // Checksum (0 to autofill)
                0,                              // Urgent pointer
                LIBNET_TCP_H,                   // Length of the TCP packet (no data means only the header size)
                NULL,                           // Payload (none)
                0,                              // Payload length
                l, tag);                 	// Context and tag for this packet

	if(tag < 0){
	printf("Error building TCP header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(-1);
        }

	bytes_written = libnet_write(l);//Send the RST/ACK to close the connection
	if(bytes_written == -1){
                        printf("Error writing packet: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(-1);
        }
}

int receiveSYN(const struct pcap_pkthdr *header, const u_char *packet, struct timeval* before){
	const struct libnet_tcp_hdr* tcp;
        long rtt = ((header->ts.tv_sec - before->tv_sec)*1000L+header->ts.tv_usec/1000) - before->tv_usec/1000;
	
	tcp = (struct libnet_tcp_hdr*)(packet+LIBNET_ETH_H+LIBNET_IPV4_H);
	if(tcp->th_ack != htonl(1)) //Not our packet
		return 0;

	if((tcp->th_flags & TH_RST) == TH_RST)
		printf("Received %d bytes from %s rtt=%ldms (Port is closed)\n", header->len, targetc, rtt);
        else if((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)){
		printf("Received %d bytes from %s rtt=%ldms (Port is open!)\n", header->len, targetc, rtt);
		closeSession();
	}else{
		printf("Unknown packet recieved...\n");
		return 0;
	} 

	host_is_up = 1;
        return 1;


}

void sendSYN(u_int32_t target, int targetPort, int times, unsigned timeout){
        int bytes_written;
        int size;
        struct bpf_program fp;          /* The compiled filter expression */
        char* filter_exp;                /* The filter expression */
        libnet_ptag_t tag = LIBNET_PTAG_INITIALIZER;
        struct pcap_pkthdr* pkthdr;
        const u_char* packet;
        int success;
        struct timeval before;

        printf("------------------Starting SYN PING------------------\n\n");
	
	targetIP = target;//We will need this to close the session
	port = targetPort;

        /*Prepare pcap to sniff our packets*/
        filter_exp = (char*)calloc(FILTER_LENGTH, sizeof(char));
        sprintf(filter_exp, FILTER_EXPRESSION_SYN, ownIPc, targetc);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf( "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                exit(-1);
        }

        /*Prepare the SYN packet*/

	tag = libnet_build_tcp(SOURCE_PORT,	// Source TCP port 
                targetPort,    			// Destination TCP port 
                htonl(0),			// Sequence number 
                ntohl(0),			// Acknowledgement number (SYN's seq # + 1)
                TH_SYN,				// Control flags (SYN flag set only)
                libnet_get_prand(LIBNET_PRu16), // Window size (randomized)
                0,                              // Checksum (0 to autofill)
                0,                              // Urgent pointer
                LIBNET_TCP_H,                   // Length of the TCP packet (no data means only the header size)
                NULL,                           // Payload (none)
                0,                              // Payload length
                l, tag);                 	// Context and tag for this packet

	if(tag < 0){
	printf("Error building TCP header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(-1);
        }

	if(libnet_autobuild_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H, IPPROTO_TCP, target, l) == -1 ){
                printf("Error building IP header: %s\n", libnet_geterror(l));
                libnet_destroy(l);
                exit(-1);
        }

        size = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H;

        /*Send the packets*/
        if(times > 0)
                printf("Sending %d x %d bytes to port %d...\n", times, size, targetPort);
        else
                printf("Sending %d bytes to port %d in an infinite cycle...\n", size, targetPort);
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
                                printf("Request timed out (There might be a firewall!)\n");
                                break;
                        }else if(success < 0){
                                printf("An error ocurred while capturing a packet.\n");
                                break;
                        }
                }while(!receiveSYN(pkthdr, packet, &before));

                if(times==1)
                        break;
                if(times>0)
                 times--;
        }

        if(host_is_up)
                printf("------------------Host is up-----------------\n\n");
        else
                printf("------------------SYN PING INCONCLUSIVE------\n\n");

}


