OBJS = ICMP.o ARP.o SYN.o ACK.o ArbitraryTCP.o warping.o
CFLAGS = -Wall 
LIBS = -lnet -lpcap

all: $(OBJS)
	gcc $(CFLAGS) -o warping $(OBJS) $(LIBS) 

clean: 	
	-rm warping
	-rm *.o
