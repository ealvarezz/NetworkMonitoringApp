#ifndef DUMP
#define DUMP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define TCP 6
#define UDP 17
#define ICMP 1
#define IP 0

/* Ethernet header */
struct sniff_ethernet {
    u_char dmac_adress[ETHER_ADDR_LEN]; /* Destination host address */
    u_char smac_address[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};


char *expression; /* The expression for BPF filtering */

bool reading_file; /* This packet sniffer will prioritize pcap files 
			   over interfaces. If this is equal to true then
			   the sniffer will read from pcap file */

char *token; /* This must contained in the payload of the packet */

const char *usage = 
    "mydump [-i interface] [-r file] [-s string] expression\n\n"
    "-i  Live capture from the network device <interface> (e.g., eth0). If not\n"
    "    specified, mydump should automatically select a default interface to\n"
    "    listen on\n\n"
    "-r  Read packets from <file> in tcpdump format\n\n"
    "-s  Keep only packets that contain <string> in their payload\n\n"
    "<expression> is a BPF filter that specifies which packets will be dumped.\n";



void process_device(char*);


void process_pcapfile(char*);


void got_packet(u_char*, const struct pcap_pkthdr*, const u_char*);


void print_ip(u_int);


void print_time(const struct pcap_pkthdr*);


bool process_tcp(const struct iphdr*, u_int, const u_char*);


bool process_udp(const struct iphdr*, u_int, const u_char*);


bool process_icmp(const struct iphdr*, u_int, const u_char*);


bool process_other(const struct iphdr*, u_int, const u_char*);


#endif
