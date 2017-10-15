#include "mydump.h"

int main(int argc, char** argv){
    
    int opt;
    char *dev, *pcap_file;
    
    reading_file = false;
    dev = NULL; pcap_file = NULL;

    while ((opt = getopt(argc, argv, "i:r:s:")) != -1) {
	  
	  switch (opt) {
		
		case 'i':
		    dev = optarg;
		    break;
		case 'r':
		    pcap_file = optarg;
		    reading_file = true;
		    break;
		case 's':
		    token = optarg;
		    break;
		default: 
		    printf("%s",usage);
		    exit(EXIT_FAILURE);
	  }
    }
    
    //printf("BPF: %s\nDevice: %s\n\n", token, dev);
    if(reading_file)  process_pcapfile(pcap_file);
    else process_device(dev);
    
    return 0;

}

void process_device(char *dev){
   
    pcap_t *handle;			/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;			/* Netmask */
    bpf_u_int32 net;			/* My IP */


    if(dev == NULL) {
	  /* If no device is given to us then this will find default  */
	  dev = pcap_lookupdev(errbuf);
	  if (dev == NULL) {
		
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	  }
	  
    }

    /* Lookup properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	  fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
	  net = 0;
	  mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	  
	  fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	  exit(EXIT_FAILURE);
    }

    /* This is to make sure this is in a ethernet device  */
    if (pcap_datalink(handle) != DLT_EN10MB) {
	  fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, token, 0, net) == -1) {
	  fprintf(stderr, "Couldn't parse filter %s: %s\n", expression, pcap_geterr(handle));
	  exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
	  fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
	  exit(EXIT_FAILURE);
    }
    
   
    /* This will start capturing packets in a loop */
    pcap_loop(handle, -1, got_packet, NULL);
    
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    
}

void process_pcapfile(char *pcap_file){
    

    
}

 void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    bool failed_packet;
    u_int iphdr_len;
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct iphdr *ip; /* The IP header */
    struct sniffed_packet *print_packet;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    print_packet = malloc(sizeof (struct sniffed_packet));
   
    /* We get the source and destination MAC addresses */
    print_packet->dest_mac = ethernet->dmac_adress;
    print_packet->src_mac = ethernet->smac_address;

    /* We get the length of the packet */
    print_packet->len = header->len;
   
    /* We get the destination and source IP addresses */
    print_packet->dest_ip = (u_int) ip->daddr;
    print_packet->src_ip = (u_int) ip->saddr;
    
    /* We get the EtherType for the ethernet header */
    print_packet->ether_type = ethernet->ether_type;
  
    /* This is the timestamp for when the packet was camptured */
    print_packet->timestamp = header->ts;
    
    /* We need to check we have a valid IP header */ 
    iphdr_len = ip->ihl * 4;
    if (iphdr_len < 20) {             
	  printf("* Invalid IP header length: %u bytes\n\n", iphdr_len);
	  return;
    }
    
    /* Now we check what protocol we have and proceed accordingly */
    switch(ip->protocol) {
             
	  case TCP: 
		process_tcp(ip, iphdr_len, packet, print_packet); 
		break;
        case UDP: 
		process_udp(ip, iphdr_len, packet, print_packet); 
		break;
        case ICMP: 
		process_icmp(ip, iphdr_len, packet, print_packet); 
		break;
        default: 	
		process_other(ip, iphdr_len, packet, print_packet); 
		break;
    }
    
    free(print_packet);

 }

void process_tcp(const struct iphdr *ip, u_int len, const u_char *packet, struct sniffed_packet *print_packet){
    
    const struct tcphdr *tcp;       /* The TCP header */
    const char *payload;            /* Packet payload */
    int tcp_size;	/* TPC size */
   
    /* Getting tcp struct by adding ethernet size and ip size */
    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + len);
    tcp_size = tcp->doff * 4;

    if (tcp_size < 20) {
	  print_ethernet(print_packet);
	  printf("* Invalid TCP header length: %u bytes\n\n", tcp_size);
        return;
    }
    
    /* We get source and destination port numbers */
    print_packet->dest_port = ntohs(tcp->dest);
    print_packet->src_port = ntohs(tcp->source);
    
    
    /* Now we get the payload */
    payload = (u_char *) (packet + SIZE_ETHERNET + len + tcp_size);
    print_packet->payload = payload;
    print_packet->payload_size = ntohs(ip->tot_len) - (tcp_size + (ip->ihl * 4));
    memcpy(print_packet->protocol, "TCP\0", 4);

    print_ethernet(print_packet);
    print_datagram(print_packet, true);

}

void  process_udp(const struct iphdr *ip, u_int len, const u_char *packet, struct sniffed_packet *print_packet){

    const struct udphdr *udp;       /* The TCP header */
    const char *payload;            /* Packet payload */
    int udp_size;	/* TPC size */
   
    /* Getting tcp struct by adding ethernet size and ip size */
    udp = (struct udphdr*)(packet + SIZE_ETHERNET + len);
    
    /* Getting the UDP length */
    udp_size = udp->len;
    
    /* UDP length must be at least 8 bytes */
    if (udp_size < 8) {
	  print_ethernet(print_packet);
	  printf("* Invalid UDP header length: %u bytes\n\n", udp_size);
        return;
    }
    
    /* We get source and destination port numbers */
    print_packet->dest_port = ntohs(udp->dest);
    print_packet->src_port = ntohs(udp->source);
    
    
    /* Now we get the payload */
    payload = (u_char *) (packet + SIZE_ETHERNET + len + sizeof(struct udphdr)) - 28;
    print_packet->payload = payload;
    print_packet->payload_size = ntohs(ip->tot_len) - ((sizeof(struct udphdr)+ (ip->ihl * 4))) + 28;
    memcpy(print_packet->protocol, "UDP\0", 4);

    print_ethernet(print_packet);
    print_datagram(print_packet, true);
}

void process_icmp(const struct iphdr *ip, u_int len, const u_char *packet, struct sniffed_packet *print_packet){

    printf("Protocol: ICMP\n\n");
}

void  process_other(const struct iphdr *ip, u_int len, const u_char *packet, struct sniffed_packet *print_packet){

    printf("Protocol: OTHER\n\n");
}

void print_ip(u_int ip){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void print_time(struct timeval ts){
    
    char tmbuf[64], buf[64];
    time_t th_time;
    struct tm *my_tm;
    
    th_time = ts.tv_sec;
    my_tm = localtime(&th_time);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", my_tm);
    snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, ts.tv_usec);
    printf("%s", buf);
}

void print_datagram(struct sniffed_packet *print_packet, bool ports){
    
    if(ports){
	  print_ip(print_packet->src_ip);
	  printf(":%d -> ", print_packet->src_port);
	  print_ip(print_packet->dest_ip);
	  printf(":%d", print_packet->dest_port);
    }
    else{ 
	  print_ip(print_packet->src_ip);
	  printf(" -> ");
	  print_ip(print_packet->dest_ip);
    }
    
    printf(" %s\n", print_packet->protocol);
    print_payload(print_packet->payload, print_packet->payload_size);
    printf("\n");
}

void print_ethernet(struct sniffed_packet *print_packet){

    const u_char *smac, *dmac;
    smac = print_packet->src_mac;
    dmac = print_packet->dest_mac;
    
    print_time(print_packet->timestamp);

    printf(" %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X", smac[0], smac[1],smac[2],smac[3],smac[4],smac[5], dmac[0], dmac[1],dmac[2],dmac[3],dmac[4],dmac[5]);

    printf(" type: 0x%X%02X len %d\n", print_packet->ether_type & 0xFF, print_packet->ether_type >> 8 & 0xFF, print_packet->len);

}

void print_hex_ascii_line(const u_char *payload, int len, int offset){

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_payload(const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;		/* number of bytes per line */
	int line_len;
	int offset = 0;			/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

