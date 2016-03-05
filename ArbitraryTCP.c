#include <libnet.h>

#include "ArbitraryTCP.h"

extern libnet_t* l;

#define SOURCE_PORT 666

void sendArbitraryTCP(u_int32_t target, int targetPort, int times, u_char flags, int sequenceNum, int ackNum){
        int bytes_written;
        int size;
        libnet_ptag_t tag = LIBNET_PTAG_INITIALIZER;

        printf("------------------Sending Custom TCP PACKET------------------\n\n");
	
        /*Prepare the Custom packet*/

	tag = libnet_build_tcp(SOURCE_PORT,	// Source TCP port 
                targetPort,    			// Destination TCP port 
                htonl(sequenceNum),		// Sequence number 
                ntohl(ackNum),			// Acknowledgement number
		flags,				// Control flags
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
                bytes_written = libnet_write(l);
                if(bytes_written == -1){
                        printf("Error writing packet: %s\n", libnet_geterror(l));
                        libnet_destroy(l);
                        exit(-1);
                }

                if(times==1)
                        break;
                if(times>0)
                	times--;
        }
}


