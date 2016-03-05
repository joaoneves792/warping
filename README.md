# warping
Tool to check if a host is up using several methods.

#Disclaimer
I wrote this tool as an educational exercise to learn how to use libpcap and libnet, it should probably not be used in the real world! (there are other far better tools out there to achieve the same goals).

#Usage
```
Usage: sudo warping <target ip> [options]

Warping v1.0 by joao neves 20/11/2013

OPTIONS:

	-i <interface>
	Specify an interface to use when sending the packets. If none is suplied then it uses the default one.

	-n <count>
	Stop after sending count number of packets. If count is -1 then keep sending until the user kills the
	program.

	-w <timeout>
	Time (in ms) to wait for a response from the target

	-p <port>
	Number of the port on the target to send SYN or ACK packets. Might be usefull to check if that port is 
	open or to evade a firewall.

	-icmp
	Send ICMP ECHO requests and wait for the replies(normal ping).

	-arp
	Do an ARP ping. Basicly it sends an ARP Request (Who is) and waits for the reply. Only works if you are
	on the same subnet as the target, but if you are then the lack of a response can only mean that the host 
	is really down.

	-syn
	Send a SYN packet to a port on the target machine (default is 80, but you can choose another one with
	-p). The target can either reply with a SYN/ACK packet meaning that the host is up and that port is
	open, or with a RST packet, meaning that the host is up but that port is closed, if it times out it
	might mean that the host is down or that there is a firewall in place.

	-ack
	Send an ACK packet to a port on the target machine (default is 80, but you can choose another one with
	-p). The host can either respond with a RST packet, meaning that it is up, or if it times out the host
	might	be down or it is firewalled. This is the most stealth kind of ping since it is relatively
	undetectable.
	
	-custom
	Send custom TCP packets. Use the flags -s -a -f and -p to customize the fields of the TCP packet.
	
	-s
	Set the sequence number for the custom TCP packet.
	
	-a
	Set the ack number for the custom TCP packet.
	
	-f <flag,flag,...>
	Set the flags for the custom TCP packet.
```
