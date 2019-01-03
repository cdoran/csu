/*

  Charles Doran
  CS 557
  HW 2

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
#include "fsniffer.h"

// Session handle reference. Global so we can call pcap_breakloop() from a signal handler.  
pcap_t* _alarm_timeout_handle; 

// get protocol as string
const char* print_proto(int p) {
   if(p == IPPROTO_TCP) 
       return "TCP";
   if(p == IPPROTO_UDP) 
       return "UDP";
   if(p == IPPROTO_ICMP) 
       return "ICMP";
    return "";
}

// get flow direction as string
const char* print_dir(int d) {
  if(d == DIR_SRC_DST)
      return " ->";
  if(d == DIR_DST_SRC)
      return "<- ";
  if(d == DIR_BOTH)
      return "<->";
  return " - ";
}

// get time as string as specified in project description
char* print_start_time(struct timeval tv, char* time_stamp) {
    char* t = ctime((const time_t*) &(tv.tv_sec));
    strncpy(time_stamp, t + 11, 8);
    sprintf(time_stamp + 8, ".%d", (int)tv.tv_usec);
    return time_stamp;
}

// print flow table header
void print_head() {
    printf("%-15s %-5s %-16s %-6s %-4s %-16s %-8s %-8s %-9s %-8s %-12s\n", "StartTime","Proto", "SrcAddr", "SPort", 
           "Dir", "DstAddr", "DPort", "TotPkts", "TotBytes", "State", "Dur");
}

// print single flow
void print_flow(flow* f) {
    char time_stamp[16] = {0};
    printf("%-15s %-5s %-16s %-6d %-4s %-16s %-8d %-8d %-9d %-8s %d.%d\n", print_start_time(f->start, time_stamp),  
           print_proto(f->proto), f->ip_src, f->src_port, print_dir(f->dir), f->ip_dst, f->dst_port, f->tot_pkts, 
           f->tot_bytes, f->state, (int)f->dur.tv_sec, (int)f->dur.tv_usec);
}

// print flows
void print_flows(flow_mngr* fm){
    int i;
    int stop = fm->flows_len;
    if(fm->records > 0) 
        if((stop = fm->records - fm->exported) > fm->flows_len)
            stop = fm->flows_len;
    for(i=0; i<stop; i++)
        print_flow(fm->flows + i);
}

// initialize flow manager struct 
flow_mngr* fm_init(int t, int o, int num, int secs) {
    flow_mngr* fm; 
    fm = (flow_mngr*) malloc(sizeof(flow_mngr));
    fm->time = t;
    fm->offset = o;
    fm->records = num;
    fm->timeout = secs;
    fm->exported = 0;
    fm->flows_len = 0;
    fm->flows = (flow*) malloc(sizeof(flow) * ARRAY_BLOCK);
    fm->capacity = ARRAY_BLOCK;
    print_head();
    return fm;
}

// put a flow into flow array
int push_flows(flow_mngr* fm, flow f) {
    fm->flows[fm->flows_len++] = f;
    if (fm->flows_len == fm->capacity) { // need to have array capacity var
        fm->capacity += ARRAY_BLOCK;
        fm->flows = (flow*) realloc(fm->flows, sizeof(flow) * fm->capacity);
    }
    return fm->flows_len;
}

// export flow if we have reached timeout
int export_flow(flow_mngr* fm, int i) {
    int j;
    if((fm->records > 0) && (fm->exported >= fm->records)) // dont print anymore exiting. 
        return fm->flows_len;
    print_flow(fm->flows + i);
    for(j=i; j<fm->flows_len-1; j++) 
        fm->flows[j] = fm->flows[j+1];
    fm->exported++;
    fm->flows_len--;
    if(fm->exported == fm->records)
        pcap_breakloop(fm->handle);
    return fm->flows_len;
}

// a flow is defined by protocol and ip:port pairs
int exists_in_flows(flow_mngr* fm, flow_pkt* pkt_data) {
    int i;
    for(i=0; i<fm->flows_len; i++) { 
        if(fm->flows[i].proto == pkt_data->proto) {
            if(!strcmp(fm->flows[i].ip_src, pkt_data->ip_src) && fm->flows[i].src_port == pkt_data->src_port && 
               !strcmp(fm->flows[i].ip_dst, pkt_data->ip_dst) && fm->flows[i].dst_port == pkt_data->dst_port)
                return i;
            if(!strcmp(fm->flows[i].ip_src, pkt_data->ip_dst) && fm->flows[i].src_port == pkt_data->dst_port &&
               !strcmp(fm->flows[i].ip_dst, pkt_data->ip_src) && fm->flows[i].dst_port == pkt_data->src_port)
                return i;
        }
    }
    return -1;
}

// add a packet that is part of an existing flow
int update_existing_flow(flow_mngr* fm, int i, flow_pkt* pkt_data) {
    fm->flows[i].tot_pkts++;
    fm->flows[i].tot_bytes += pkt_data->len;
    strcpy(fm->flows[i].state, pkt_data->state);
    fm->flows[i].dur.tv_sec = pkt_data->ts.tv_sec - fm->flows[i].start.tv_sec;
    if(pkt_data->ts.tv_usec < fm->flows[i].start.tv_usec) {
        fm->flows[i].dur.tv_sec -= 1;
        pkt_data->ts.tv_usec += 1000000;
    }
    fm->flows[i].dur.tv_usec = pkt_data->ts.tv_usec - fm->flows[i].start.tv_usec;
    if(fm->flows[i].proto != IPPROTO_TCP && fm->flows[i].ip_src != pkt_data->ip_src)
        fm->flows[i].dir = DIR_BOTH;
    return i;
}

// add a packet that starts a new flow
int add_new_flow(flow_mngr* fm, flow_pkt* fp) {
    flow f;
    f.start = fp->ts;
    f.proto = fp->proto;
    strcpy(f.ip_src, fp->ip_src);
    strcpy(f.ip_dst, fp->ip_dst);
    f.src_port = fp->src_port;  
    f.dst_port = fp->dst_port;
    f.tot_pkts = 1;
    f.tot_bytes = fp->len;
    strcpy(f.state, fp->state);
    f.dur.tv_sec = 0;
    f.dur.tv_usec = 0;
    if(f.proto == IPPROTO_TCP) {
        if(strcmp(f.state, "SYN") == 0)
            f.dir = DIR_SRC_DST;
        else if(strcmp(f.state, "SYNACK") == 0)
            f.dir = DIR_DST_SRC;
        else
            f.dir = DIR_UNKNOWN;
    } else {
        f.dir = DIR_SRC_DST;
    }
    return push_flows(fm, f);
}

// timeout flow
int timeout_flow(flow_mngr* fm, int i, flow_pkt* pkt_data) {
   struct timeval temp; 
   temp.tv_sec = pkt_data->ts.tv_sec - fm->flows[i].start.tv_sec; // new duration in seconds
   temp.tv_usec = pkt_data->ts.tv_usec - fm->flows[i].start.tv_usec;
   if(pkt_data->ts.tv_usec < fm->flows[i].dur.tv_usec) {
        temp.tv_sec -= 1;
        temp.tv_usec += 1000000;
    }
    if((temp.tv_sec > fm->timeout) || (temp.tv_sec == fm->timeout && temp.tv_usec >= 0)) {
        export_flow(fm, i);
        return 1;
    }
    return 0;
}

// place newly captured packet into flows
int update_flows(flow_mngr* fm, flow_pkt* pkt_data) {
    int i;
    if((i = exists_in_flows(fm, pkt_data)) >= 0) 
        if(timeout_flow(fm, i, pkt_data) == 0) 
           return update_existing_flow(fm, i, pkt_data);
    return add_new_flow(fm, pkt_data); 
}

// create tcp packet struct from buffer and print data. 
void process_tcp(flow_mngr* fm, const u_char *packet, flow_pkt* pkt_data) {
    
    const struct sniff_tcp *tcp_pkt;
    int size_hdr;
    
    tcp_pkt = (struct sniff_tcp*) packet;
    size_hdr = TH_OFF(tcp_pkt)*4;
   
    if(size_hdr < 20) {
        printf("Invalid TCP header length: %d", size_hdr);
        return;  
    }
  
    pkt_data->src_port = ntohs(tcp_pkt->th_sport); 
    pkt_data->dst_port = ntohs(tcp_pkt->th_dport);
    if((tcp_pkt->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        strcpy(pkt_data->state, "SYNACK");
    else if((tcp_pkt->th_flags & TH_SYN) == TH_SYN)
        strcpy(pkt_data->state, "SYN");
    else if((tcp_pkt->th_flags & TH_FIN) == TH_FIN)
        strcpy(pkt_data->state, "FIN");
    else if((tcp_pkt->th_flags & TH_RST) == TH_RST)
        strcpy(pkt_data->state, "RST");
    else 
        strcpy(pkt_data->state, "EST");

    //printf("Source Port: %d\n", ntohs(tcp_pkt->th_sport));
    //printf("Destination Port: %d\n", ntohs(tcp_pkt->th_dport));
    //printf("Flags: %x\n", tcp_pkt->th_flags);
    //printf(" FIN: %x\n", tcp_pkt->th_flags & TH_FIN);
    //printf(" SYN: %x\n", (tcp_pkt->th_flags & TH_SYN) >> 1);
    //printf(" RST: %x\n", (tcp_pkt->th_flags & TH_RST) >> 2);
    //printf(" PUSH: %x\n", (tcp_pkt->th_flags & TH_PUSH) >> 3);
    //printf(" ACK: %x\n", (tcp_pkt->th_flags & TH_ACK) >> 4);
    //printf(" URG: %x\n", (tcp_pkt->th_flags & TH_URG) >> 5);
    //printf(" ECE: %x\n", (tcp_pkt->th_flags & TH_ECE) >> 6);
    //printf(" CWR: %x\n", (tcp_pkt->th_flags & TH_CWR) >> 7); 
    //printf("Sequence Number: %u\n", tcp_pkt->th_seq);
    //printf("Ack number: %u\n", tcp_pkt->th_ack); 
    
    update_flows(fm, pkt_data);
  
    return;

}

// create udp packet struct from buffer and print data
void process_udp(flow_mngr* fm, const u_char *packet, flow_pkt* pkt_data) {

    const struct sniff_udp *udp_pkt;
    
    udp_pkt = (struct sniff_udp*) packet;
    
    pkt_data->src_port = ntohs(udp_pkt->uh_sport); 
    pkt_data->dst_port = ntohs(udp_pkt->uh_dport);
    strcpy(pkt_data->state, "");
    //printf("Source Port: %d\n", ntohs(udp_pkt->uh_sport));
    //printf("Destination Port: %d\n", ntohs(udp_pkt->uh_dport));
  
    update_flows(fm, pkt_data);
    
    return;

}

// create icmp packet struct from buffer and print data
void process_icmp(flow_mngr* fm, const u_char *packet, flow_pkt* pkt_data) {

    const struct sniff_icmp *icmp_pkt;
    
    icmp_pkt = (struct sniff_icmp*) packet;
   
    pkt_data->src_port = 0; 
    pkt_data->dst_port = 0;
    snprintf(pkt_data->state, STATE_LEN, "%d", icmp_pkt->ih_type);
    //printf("Type: %d\n", icmp_pkt->ih_type);
    //printf("Code: %d\n", icmp_pkt->ih_code);
    
    update_flows(fm, pkt_data);
    
    return;

}

// parse raw packet, this is function passed to pcap_loop()
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
    //static int count = 1;
    static int first = 0;
    static time_t start = 0;
    static time_t end = 0;
    const struct sniff_ethernet *eth_pkt;
    const struct sniff_ip *ip_pkt;
    int size_ip;
    flow_pkt pkt_data;
    flow_mngr* fm;

    fm = (flow_mngr*) args;
    
    if(first == 0) {
        start = header->ts.tv_sec + fm->offset;
        end = header->ts.tv_sec + fm->time; 
        first = 1;
    }  
     
    if(header->ts.tv_sec > end)
        pcap_breakloop(fm->handle);

    if(header->ts.tv_sec >= start) {

        //printf("\nPacket %d;\n", count++);
        //printf("Timestamp: %s", ctime((const time_t*) &(header->ts.tv_sec)));
        //printf("Packet Length: %d\n", header->len);
        pkt_data.ts = header->ts;
        pkt_data.len = header->len;
   
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
        //printf("IP source: %s\n", inet_ntoa(ip_pkt->ip_src));
        //printf("IP destination: %s\n", inet_ntoa(ip_pkt->ip_dst));
        strncpy(pkt_data.ip_src, inet_ntoa(ip_pkt->ip_src), IP_ADDR_LEN);
        strncpy(pkt_data.ip_dst, inet_ntoa(ip_pkt->ip_dst), IP_ADDR_LEN);
        pkt_data.proto = ip_pkt->ip_p; 

        if(ip_pkt->ip_p == IPPROTO_TCP) {
	        // puts("Protocol: TCP"); 
	        process_tcp(fm, packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } else if (ip_pkt->ip_p == IPPROTO_UDP) {
	        //puts("Protocol: UDP");
	        process_udp(fm, packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } else if (ip_pkt->ip_p == IPPROTO_ICMP) {
	        //puts("Protcol: ICMP");
	        process_icmp(fm, packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } 
 
    }

    return;

}

// print usage message and exit
void usage(char* msg) {
    
    puts("Usage:\nfsniffer [-r filename] [-i interface] [-t time] [-o time_offset] [-N num] [-S secs]");
    printf("%s\n", msg);
    exit(1);

}

// get and set command line options.  Return type of file to sniff, live or offline
int get_options(int argc, char* argv[], char* dev, int* time, int* time_offset, int* num, int* secs ) {

    // command line options parsing
    extern char *optarg;
    extern int optind;
    int rflag = 0;
    int iflag = 0;
    int tflag = 0;
    int oflag = 0;
    int nflag = 0;
    int sflag = 0;
    int c;

    //*time_offset = -1;

    while ((c= getopt(argc, argv, "r:i:t:o:N:S:")) != EOF) {
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
            case 'N':
                nflag = 1;
                *num = atoi(optarg);
                break;
            case 'S':
                sflag = 1;
                *secs = atoi(optarg);
                break;
            case '?':
                usage("Invalid argument.");
                break;
            default:
                usage("Unknown error.");
        }
    }
   
    if(!(rflag ^ iflag))
        usage("Must provide either -r or -i options.");

    if(rflag)
        return OFFLINE;

    return LIVE;

}

// handle alarm signal for exitting interface sniffing
void catch_alarm(int signum) {

    pcap_breakloop(_alarm_timeout_handle);

}

// Open file for offline packet sniffing
void capture(int file_or_dev, char *dev, flow_mngr* fm) {
    
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string 
    bpf_u_int32 mask = 0; // netmask 
    bpf_u_int32 net = 0; // IP 
    struct bpf_program fp; // compiled filter 
    char filter_exp[] = "ip"; // filter expression 

    if(file_or_dev == LIVE) {

        
        /* Find the properties for the device */
        if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }

        /* Open the session in promiscuous mode */
        fm->handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(fm->handle == NULL) {
            printf("Couldn't open device %s: %s\n", dev, errbuf);
            exit(1);
        }

        _alarm_timeout_handle = fm->handle;
        signal(SIGALRM, catch_alarm);
        alarm(fm->time);

    } else {

        /* Open file */
        fm->handle = pcap_open_offline(dev, errbuf);
        if(fm->handle == NULL) {
            printf("Couldn't open file %s: %s\n", dev, errbuf);
            exit(1);
        }

    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(fm->handle) != DLT_EN10MB) {
        printf("%s is not an Ethernet\n", dev);
        exit(1);
    }

    /* Compile and apply the filter */
    if(pcap_compile(fm->handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(fm->handle));
        exit(1);
    }
	
    if(pcap_setfilter(fm->handle, &fp) == -1) {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(fm->handle));
    	exit(1);
    }

    pcap_loop(fm->handle, 0, process_packet, (u_char*) fm);
    pcap_freecode(&fp);
    
    return;

}

int main(int argc, char *argv[]) {

    int file_or_dev; // read from file or device
    char dev[255];  // device to sniff on or file to process
    int t = 60; // time to run packet capture for
    int o = 0; // time to start packet capture for files 
    int num = 0; // number of flows to print
    int secs = 60; // max duration of a flow
    flow_mngr* fm;
   
    // get the file or interface and set time parameters
    file_or_dev = get_options(argc, argv, dev, &t, &o, &num, &secs);
    fm = fm_init(t, o, num, secs);
    capture(file_or_dev, dev, fm);
	
    print_flows(fm);
    pcap_close(fm->handle);
    free(fm->flows);
    free(fm);
    return 0;

 }

