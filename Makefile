CFLAGS = -Wall 
LIBS = -lnet -lpcap
LIBS_PHONE = -lnet -lusb-1.0 -lpthread  -lnl-genl-3 -lnl-3 


all: 
	gcc $(CFLAGS) -o warping warping.c ICMP.c ARP.c SYN.c ACK.c ArbitraryTCP.c $(LIBS) 

ubuntu-phone:
	gcc $(CFLAGS) -o warping warping.c ICMP.c ARP.c SYN.c ACK.c ArbitraryTCP.c libpcap.a $(LIBS_PHONE) 

clean: 	
	rm warping
