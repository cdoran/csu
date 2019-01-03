/*

  Charles Doran
  CS 557
  HW 1

*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "sniffer.h"

// Session handle. This is global so we can call pcap_breakloop()
// from a signal handler.  
pcap_t *handle; 

// This flag indicates whether program is ended with SIGALRM or times
// are evaluated from headers in .pcap file.
int sniffer_alarm = OFF;

// create tcp packet struct from buffer and print data. 
void process_tcp(const u_char *packet) {
    
    const struct sniff_tcp *tcp_pkt;
    int size_hdr;
    
    tcp_pkt = (struct sniff_tcp*) packet;
    size_hdr = TH_OFF(tcp_pkt)*4;
   
    if(size_hdr < 20) {
        printf("Invalid TCP header length: %d", size_hdr);
        return;  
    }
  
    printf("Source Port: %d\n", ntohs(tcp_pkt->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_pkt->th_dport));
    printf("Flags: %x\n", tcp_pkt->th_flags);
    printf(" FIN: %x\n", tcp_pkt->th_flags & TH_FIN);
    printf(" SYN: %x\n", (tcp_pkt->th_flags & TH_SYN) >> 1);
    printf(" RST: %x\n", (tcp_pkt->th_flags & TH_RST) >> 2);
    printf(" PUSH: %x\n", (tcp_pkt->th_flags & TH_PUSH) >> 3);
    printf(" ACK: %x\n", (tcp_pkt->th_flags & TH_ACK) >> 4);
    printf(" URG: %x\n", (tcp_pkt->th_flags & TH_URG) >> 5);
    printf(" ECE: %x\n", (tcp_pkt->th_flags & TH_ECE) >> 6);
    printf(" CWR: %x\n", (tcp_pkt->th_flags & TH_CWR) >> 7); 
    printf("Sequence Number: %u\n", tcp_pkt->th_seq);
    printf("Ack number: %u\n", tcp_pkt->th_ack); 
  
    return;

}

// create udp packet struct from buffer and print data
void process_udp(const u_char *packet) {

    const struct sniff_udp *udp_pkt;
    
    udp_pkt = (struct sniff_udp*) packet;
  
    printf("Source Port: %d\n", ntohs(udp_pkt->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_pkt->uh_dport));
  
    return;

}

// create icmp packet struct from buffer and print data
void process_icmp(const u_char *packet) {

    const struct sniff_icmp *icmp_pkt;
    
    icmp_pkt = (struct sniff_icmp*) packet;
  
    printf("Type: %d\n", icmp_pkt->ih_type);
    printf("Code: %d\n", icmp_pkt->ih_code);
  
    return;

}

// parse raw packet, this is function passed to pcap_loop()
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
    static int count = 1;
    static int first = 0;
    static time_t start = 0;
    static time_t end = 0;
    time_offset* to;
    const struct sniff_ethernet *eth_pkt;
    const struct sniff_ip *ip_pkt;
    int size_ip;
    
    if(first == 0 && sniffer_alarm == OFF) {
        to = (time_offset*) args;
        start = header->ts.tv_sec + to->offset;
        end = header->ts.tv_sec + to->time; 
        first = 1;
    }  

    if((header->ts.tv_sec >= start) && (header->ts.tv_sec <= end) || (sniffer_alarm == ON)) {

        printf("\nPacket %d;\n", count++);
        printf("Timestamp: %s", ctime((const time_t*) &(header->ts.tv_sec)));
        printf("Packet Length: %d\n", header->len);
   
        // set ethernet packet
        eth_pkt = (struct sniff_ethernet*) (packet);

        // set ip packet
        ip_pkt = (struct sniff_ip*) (packet + SIZE_ETHERNET); 
        size_ip = IP_HL(ip_pkt)*4;
        if(size_ip < 20) {
            printf("Invalid IP header: %d bytes\n", size_ip);
            return;
        }

        // print IP source, destination
        printf("IP source: %s\n", inet_ntoa(ip_pkt->ip_src));
        printf("IP destination: %s\n", inet_ntoa(ip_pkt->ip_dst));

        if(ip_pkt->ip_p == IPPROTO_TCP) {
	    puts("Protocol: TCP"); 
	    process_tcp(packet + SIZE_ETHERNET + size_ip);
        } else if (ip_pkt->ip_p == IPPROTO_UDP) {
	    puts("Protocol: UDP");
	    process_udp(packet + SIZE_ETHERNET + size_ip);
        } else if (ip_pkt->ip_p == IPPROTO_ICMP) {
	    puts("Protcol: ICMP");
	    process_icmp(packet + SIZE_ETHERNET + size_ip);
        } 
 
    }

    return;

}

// print usage message and exit
void usage(char* msg) {
    
    puts("Usage:\nsniffer [-r filename] [-i interface] [-t time] [-o time_offset]");
    printf("%s\n", msg);
    exit(1);

}

// get and set command line options.  Return type of file to sniff, live or offline
int get_options(int argc, char *argv[], char *dev, int* time, int *time_offset) {

    // command line options parsing
    extern char *optarg;
    extern int optind;
    int rflag = 0;
    int iflag = 0;
    int tflag = 0;
    int oflag = 0;
    int c;

    //*time_offset = -1;

    while ((c= getopt(argc, argv, "r:i:t:o:")) != EOF) {
        switch(c) {
            case 'r':
                rflag = 1;
                strcpy(dev, optarg);
                break;
            case 'i':
                iflag = 1;
                strcpy(dev, optarg);
                break;
            case 't':
                tflag = 1;
                *time = atoi(optarg);
                break;
            case 'o':
                oflag = 1;
                *time_offset = atoi(optarg);
                break;
            case '?':
                usage("Invalid argument.");
            default:
                usage("Unknown error.");
        }
    }
   
    if(!(rflag ^ iflag))
        usage("Must provide either -r or -i options.");

    if(!tflag)
        usage("Must provide -t option.");

    if(rflag)
        return OFFLINE;

    return LIVE;

}

// handle alarm signal for exitting interface sniffing
void timeout(int signum) {

    pcap_breakloop(handle);

}

// Set the filter.  This compiles, sets and frees the filter.  It seems we can 
// delete filter after we have applied it to the handle
void filter(pcap_t *handle, bpf_u_int32 net) {
    
    struct bpf_program fp; // compiled filter 
    char filter_exp[] = "ip"; // filter expression 

    /* Compile and apply the filter */
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }
	
    if(pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	exit(1);
    }

    pcap_freecode(&fp);	

    return;

}

// Read device for live packet sniffing 
void capture_live(char *dev, int time) {
    
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string 
    bpf_u_int32 mask; // netmask 
    bpf_u_int32 net; // IP 

    /* Find the properties for the device */
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("%s is not an Ethernet\n", dev);
        exit(1);
    }

    signal(SIGALRM, timeout);
    alarm(time);
    sniffer_alarm = ON;
    filter(handle, net); 

    pcap_loop(handle, 0, process_packet, NULL);
 
    return;

}

// Open file for offline packet sniffing
void capture_offline(char *dev, int t, int o) {
    
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string 
    time_offset to;

    to.time = t;
    to.offset = o;

    /* Open file */
    handle = pcap_open_offline(dev, errbuf);
    if(handle == NULL) {
        printf("Couldn't open file %s: %s\n", dev, errbuf);
        exit(1);
    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        printf("%s is not an Ethernet\n", dev);
        exit(1);
    }
    filter(handle, 0); 

    pcap_loop(handle, 0, process_packet, (u_char*) &to);
 
    return;

}

int main(int argc, char *argv[]) {

    int file_or_dev; // read from file or device
    char dev[255];  // device to sniff on or file to process
    int t = 0; // time to run packet capture for
    int o = 0; // time to start packet capture for files 
   
    // get the file or interface and set time parameters
    file_or_dev = get_options(argc, argv, dev, &t, &o);

    if(file_or_dev == LIVE) {
        capture_live(dev, t);
    } else if(file_or_dev == OFFLINE) {
        capture_offline(dev, t, o);
    } 
	
    pcap_close(handle);
    return(0);

 }

