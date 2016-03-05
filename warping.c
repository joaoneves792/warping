#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libnet.h>
#include <pcap.h>

#include "ICMP.h"
#include "ARP.h"
#include "SYN.h"
#include "ACK.h"
#include "ArbitraryTCP.h"

#define IP_CHAR_LEN 16
#define DEFAULT_REPEAT_COUNT 4
#define DEFAULT_TARGET_PORT 80
#define TIMEOUT_MS 4000

#define USED_DEFINED 0
#define ICMP 1
#define ARP 2
#define SYN 3
#define ACK 4

libnet_t* l; /*libnet context*/
char libneterrbuf[LIBNET_ERRBUF_SIZE];
char pcaperrbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle;
char ownIPc[IP_CHAR_LEN];
u_int32_t ownIP;
char* targetc;
bpf_u_int32 net;        
int host_is_up = 0;
char* dev = NULL;

int main(int argc, char** argv){
        bpf_u_int32 mask;               /* The netmask of our sniffing device */

	u_int32_t targetIP, tmp1, tmp2;
	int sameSubnet = 0;
	int i;
	int times = DEFAULT_REPEAT_COUNT;
	int timeout = TIMEOUT_MS;
	int targetPort = DEFAULT_TARGET_PORT;
	char preferredPing[5]; //[0] there is a preferred scan, [1] do ICMP, [2] do ARP(if possible), [3] do SYN, [4] do ACK
	/*Variables for sending arbitrary TCP packets, and their default values*/
	int sendCustomPackets = 0;
	int sequence = 1;
	int ackNumber = 1;
	char* flagPtr;
	u_char tcpFlags = 0;
	/*--------------*/

	if(argc < 2){
		printf("Usage: sudo warping <target ip> [options]\n\nWarping v1.0 by warpenguin 20/11/2013\n\nOPTIONS:\n\n	-i <interface>\n	Specify an interface to use when sending the packets. If none is suplied then it uses the default one.\n\n	-n <count>\n	Stop after sending count number of packets. If count is -1 then keep sending until the user kills the program.\n\n	-w <timeout>\n	Time (in ms) to wait for a response from the target\n\n	-p <port>\n	Number of the port on the target to send SYN or ACK packets. Might be usefull to check if that port is open or to evade a firewall.\n\n	-icmp\n	Send ICMP ECHO requests and wait for the replies(normal ping).\n\n	-arp\n	Do an ARP ping. Basicly it sends an ARP Request (Who is) and waits for the reply. Only works if you are on the same subnet as the target, but if you are then the lack of a response can only mean that the host is really down.\n\n	-syn\n	Send a SYN packet to a port on the target machine (default is 80, but you can choose another one with -p). The target can either reply with a SYN/ACK packet meaning that the host is up and that port is open, or with a RST packet, meaning that the host is up but that port is closed, if it times out it might mean that the host is down or that there is a firewall in place.\n\n	-ack\n	Send an ACK packet to a port on the target machine (default is 80, but you can choose another one with -p). The host can either respond with a RST packet, meaning that it is up, or if it times out the host might be down or it is firewalled. This is the most stealth kind of ping since it is relatively undetectable.\n\n");
		return 0;
	}

	if(geteuid() != 0)
	{
		printf("Warping must run as root (to use libnet and pcap).\n");
		return -1;
	}

	/*Get the target ip*/
	if( (targetIP = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE)) == -1){
		printf("Target IP address is malformed or DNS lookup failed\n");
		return -1;
	}
	targetc = libnet_addr2name4(targetIP, LIBNET_DONT_RESOLVE);

	//initialize the preferred ping array with zeros
	for(i=0;i<5;i++)	
		preferredPing[i] = 0;

	/*Get the options*/
	for (i = 2; i < argc; i++)
                if (!strcmp(argv[i], "-i"))
                        dev = argv[++i];
                else if (!strcmp(argv[i], "-n"))
                        times = atoi(argv[++i]);
		else if(!strcmp(argv[i], "-w"))
			timeout = atoi(argv[++i]);
		else if(!strcmp(argv[i], "-p"))
			targetPort = atoi(argv[++i]);
		else if(!strcmp(argv[i], "-icmp")){
			preferredPing[USED_DEFINED] = 1;
			preferredPing[ICMP] = 1;
		}else if(!strcmp(argv[i], "-arp")){
			preferredPing[USED_DEFINED] = 1;
			preferredPing[ARP] = 1;
		}else if(!strcmp(argv[i], "-syn")){
			preferredPing[USED_DEFINED] = 1;
			preferredPing[SYN] = 1;
		}else if(!strcmp(argv[i], "-ack")){
			preferredPing[USED_DEFINED] = 1;
			preferredPing[ACK] = 1;
		}else if(!strcmp(argv[i], "-custom")) /*The next options are exclusive to sending custom tcp packets*/
			sendCustomPackets = 1;
		else if(!strcmp(argv[i], "-s"))
			sequence = atoi(argv[++i]);
		else if(!strcmp(argv[i], "-a"))
			ackNumber = atoi(argv[++i]);
		else if(!strcmp(argv[i], "-f")){
			flagPtr = strtok(argv[++i], ",");
			while(flagPtr){
				if(!strcmp(flagPtr, "SYN"))
					tcpFlags = tcpFlags | TH_SYN;
				else if(!strcmp(flagPtr, "ACK"))
					tcpFlags = tcpFlags | TH_ACK;
				else if(!strcmp(flagPtr, "FIN"))
					tcpFlags = tcpFlags | TH_FIN;
				else if(!strcmp(flagPtr, "RST"))
					tcpFlags = tcpFlags | TH_RST;
				else if(!strcmp(flagPtr, "PSH"))
					tcpFlags = tcpFlags | TH_PUSH;
				else if(!strcmp(flagPtr, "URG"))
					tcpFlags = tcpFlags | TH_URG;
				else if(!strcmp(flagPtr, "ECE"))
					tcpFlags = tcpFlags | TH_ECE;
				else if(!strcmp(flagPtr, "CWR"))
					tcpFlags = tcpFlags | TH_CWR;
				flagPtr = strtok(NULL, ",");
			}		
		}
		

        if(dev == NULL){
        //Try to get the default device thru pcap 
                dev = pcap_lookupdev(pcaperrbuf);
                if (dev == NULL) {
                        printf("Couldn't find default device: %s\n", pcaperrbuf);
                        return(-1);
                }
        }

        //Init libnet context
        l = libnet_init(LIBNET_RAW4, dev, libneterrbuf);
        if ( l == NULL ) {
                printf("libnet_init() failed: %s\n", libneterrbuf);
                exit(-1);
        }
        libnet_seed_prand(l);

        //Get our ip address using libnet
        ownIP = libnet_get_ipaddr4(l);
        sprintf(ownIPc, "%s", libnet_addr2name4(ownIP, LIBNET_DONT_RESOLVE));

        printf("Using interface: %s\nCurrent IP adress: %s\n", dev, ownIPc);


        //More pcap stuff...
        if (pcap_lookupnet(dev, &net, &mask, pcaperrbuf) == -1) {
                printf("Can't get netmask for device %s\n", dev);
                return -1;
        }

	/*If the user requested a custom TCP packet then send it*/
	if(sendCustomPackets){
		if(!tcpFlags){
			printf("No TCP flags have been entered! Assuming SYN!\n");
			tcpFlags = TH_SYN;
		}
		sendArbitraryTCP(targetIP, targetPort, times, tcpFlags, sequence, ackNumber);
		/*Custom packets sent, we can close things up!*/
        	libnet_destroy(l);
		return 0;
	}

	/*Check if we are on the same subnet as the target (if yes then we can send arp requests*/
	tmp1 = (targetIP & mask);
	tmp2 = (ownIP & mask);
	if(tmp1 == tmp2){
		sameSubnet = 1;
		printf("You are on the same subnet as %s\n", targetc);
	}else
		printf("You are not on the same subnet as %s\n", targetc);


        handle = pcap_open_live(dev, BUFSIZ, 0, timeout, pcaperrbuf);
        if (handle == NULL) {
                printf("Couldn't open device %s: %s\n", dev, pcaperrbuf);
                return -1;
        }

	//If the user requested a specific scan then do it
	if(preferredPing[USED_DEFINED]){
		if(preferredPing[ICMP])
			sendICMP(targetIP, times);
		if(preferredPing[ARP]){
			if(!sameSubnet)
				printf("\nIn order to perform an ARP ping you must be on the same subnet as your target!!\n\n");
			else if(!strcmp(dev, "lo"))
				printf("\nYou cant do an ARP ping using the loopback interface!!\n\n");
			else
				sendARP(targetIP, times);
		}
		if(preferredPing[SYN])
			sendSYN(targetIP, targetPort, times);
		if(preferredPing[ACK])
			sendACK(targetIP, targetPort, times);
	}else{//If the user didnt specify a scan type then do all of them until one gets a positive answer		
		sendICMP(targetIP, times);
		if(!host_is_up && sameSubnet && strcmp(dev, "lo"))
			sendARP(targetIP, times);
		if(!host_is_up)
			sendSYN(targetIP, targetPort, times);
		if(!host_is_up)
			sendACK(targetIP, targetPort, times);
	}
        pcap_close(handle);
        libnet_destroy(l);

	return 0;
}
