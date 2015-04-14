CFLAGS = -Wall 
LIBS = -lnet -lpcap

all: 
	gcc $(CFLAGS) -o warping warping.c ICMP.c ARP.c SYN.c ACK.c ArbitraryTCP.c $(LIBS)

clean: 	
	rm *.o
	rm warping
