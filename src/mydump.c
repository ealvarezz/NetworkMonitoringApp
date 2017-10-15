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
    
    if(reading_file)  process_pcapfile(pcap_file);
    else process_device(dev);
    
    return 0;

}

void process_device(char *dev){
   
    pcap_t *handle;			/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Netmask */
    bpf_u_int32 net;		/* My IP */


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
    if (pcap_compile(handle, &fp, "", 0, net) == -1) {
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
    const u_char *dmac, *smac;
    
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    dmac = ethernet->dmac_adress;
    smac = ethernet->smac_address;
    

    printf("Packet Length: %d\n", header->len);
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\nSource Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", dmac[0], dmac[1],dmac[2],dmac[3],dmac[4],dmac[5], smac[0], smac[1],smac[2],smac[3],smac[4],smac[5]);
   
    printf("Source IP: ");
    print_ip( (u_int) ip->saddr);
    printf("Destination IP: ");
    print_ip( (u_int) ip->daddr);

    
    printf("EtherType: 0x%X%02X\n", ethernet->ether_type & 0xFF, ethernet->ether_type >> 8 & 0xFF);
   
    printf("Time stamp: ");
    print_time(header);
    
    iphdr_len = ip->ihl * 4;
    if (iphdr_len < 20) {             
	  printf("* Invalid IP header length: %u bytes\n\n", iphdr_len);
	  return;
    }

    switch(ip->protocol) {
             
	  case TCP: 	
		failed_packet = process_tcp(ip, iphdr_len, packet); 
		if(failed_packet == false) return;
		else break;
        case UDP: 	
		failed_packet = process_udp(ip, iphdr_len, packet); 
		if(failed_packet == false) return;
		else break;
        case ICMP: 	
		failed_packet = process_icmp(ip, iphdr_len, packet); 
		if(failed_packet == false) return;
		else break;
        default: 		
		failed_packet = process_other(ip, iphdr_len, packet); 
		if(failed_packet == false) return;
		else break;
    }


 }

bool process_tcp(const struct iphdr *ip, u_int len, const u_char *packet){
    
    u_int des_port, src_port;		/* Source and estination ports*/
    const struct tcphdr *tcp;       /* The TCP header */
    const char *payload;            /* Packet payload */
    int tcp_size, payload_size;	/* TPC size and payload size */
   
    /* Getting tcp struct by adding ethernet size and ip size */
    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + len);
    tcp_size = tcp->doff * 4;

    if (tcp_size < 20) {
	  printf("* Invalid TCP header length: %u bytes\n\n", tcp_size);
        return false;
    }

    des_port = ntohs(tcp->dest);
    src_port = ntohs(tcp->source);
    
    printf("Src port: %d\n", src_port);
    printf("Dst port: %d\n", des_port);
    
    /* Now we get the payload */
    payload = (u_char *) (packet + SIZE_ETHERNET + len + tcp_size);

    printf("Protocol: TCP\n\n");
    return true;
}

bool  process_udp(const struct iphdr *ip, u_int len, const u_char *packet){

    printf("Protocol: UDP\n\n");
    return true;
}

bool process_icmp(const struct iphdr *ip, u_int len, const u_char *packet){

    printf("Protocol: ICMP\n\n");
    return true;
}

bool  process_other(const struct iphdr *ip, u_int len, const u_char *packet){

    printf("Protocol: OTHER\n\n");
    return true;
}

void print_ip(u_int ip){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void print_time(const struct pcap_pkthdr *header){
    
    char tmbuf[64], buf[64];
    time_t th_time;
    struct tm *my_tm;
    
    th_time = header->ts.tv_sec;
    my_tm = localtime(&th_time);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", my_tm);
    snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, header->ts.tv_usec);
    printf("%s\n", buf);
}
