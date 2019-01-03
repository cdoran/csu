/*

  Charles Doran
  CS 557
  HW 3

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
#include <limits.h>
#include "fdscan.h"

pcap_t* _handle; 
scanner* _act_scan_list;
scanner* _exp_scan_list;
int _timeout; 
int _hosts;
int _ports;

// does host meet threshhold for scanner classification
int is_scanner(scanner* s) {
    if(s->hosts_scanned > _hosts || s->ports_scanned > _ports)
        return 1;
    return 0;
}

// print host and target/ports scanned
void print_hits(char* scanner_ip, char* target_ip, char* proto, hit* h) {
    printf("%-16s %-5s %-16s ", scanner_ip, proto, target_ip);
    while(h != NULL) {
        printf("%d ", h->num);
        h = h->next;
    }
    puts("");
}

// print targets for each scanner  
void print_scanner(scanner* s) {
    target* t; 
    if(is_scanner(s) == 1) {
        t = s->targets;
        while(t != NULL) {
            if(t->tcp != NULL)
                print_hits(s->ip, t->ip, "TCP", t->tcp);
            if(t->udp != NULL)
                print_hits(s->ip, t->ip, "UDP", t->udp);
            if(t->icmp != NULL)
                print_hits(s->ip, t->ip, "ICMP", t->icmp);
            t = t->next;
        }
    }
}

// print scanner summary
void print_scanners_summary(){
    scanner* s;
    printf("Summary:\n");
    printf("%-16s %-15s %-15s\n", "Scanner", "HostsScanned", "PortsScanned");
    s = _exp_scan_list;
    while(s != NULL) {
        if(is_scanner(s) == 1)
            printf("%-16s %-15d %-15d\n", s->ip, s->hosts_scanned, s->ports_scanned);
        s = s->next;
    }
    s = _act_scan_list;
    while(s != NULL) {
        if(is_scanner(s) == 1)
            printf("%-16s %-15d %-15d\n", s->ip, s->hosts_scanned, s->ports_scanned);
        s = s->next;
    }
}

// print detailed scanner report
void print_scanners_detail(){
    scanner* s;
    printf("%-16s %-5s %-16s %s\n", "Scanner", "Proto", "HostScanned", "PortsScanned/ICMP type");
    s = _exp_scan_list;
    while(s != NULL) {
        print_scanner(s);
        s = s->next;
    }
    s = _act_scan_list;
    while(s != NULL) {
        print_scanner(s);
        s = s->next;
    }
}

// add hit to linked  list 
hit* add_hit_to_list(hit** list, hit* h) {
    hit* tmp;
    if(*list == NULL) {
       *list = h;
    } else {
        tmp = *list;
        while(tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = h;
    }
    return *list;
}

// add hit to target
target* add_hit_to_target(target* t, hit* h, u_char proto) {
    if(proto == IPPROTO_TCP)
        add_hit_to_list(&t->tcp, h);
    if(proto == IPPROTO_UDP)
        add_hit_to_list(&t->udp, h);
    if(proto == IPPROTO_ICMP)
        add_hit_to_list(&t->icmp, h);
    return t;
}

// update a hit
hit* update_hit(hit* h, flow_pkt* pkt) {
    h->pkts++;
    h->bytes += pkt->len;
    h->t = pkt->ts;
    if(pkt->proto == IPPROTO_TCP || pkt->proto == IPPROTO_UDP) {
        h->num = pkt->dst_port;    
    } else if (pkt->proto ==  IPPROTO_ICMP) {
        h->num = pkt->icmp_type;  
    }
    return h;
}

// create a hit
hit* create_hit(flow_pkt* pkt) {
    hit* h = malloc(sizeof(hit));
    h->pkts = 0;
    h->bytes = 0;
    h->next = NULL;
    return update_hit(h, pkt);
}

// does hit exist in linked list
hit* hit_exists_in_list(hit* h, int num) {
    while(h != NULL) {
        if(h->num == num)
            return h;
        h = h->next;
    }
    return NULL;

}

// does hit exists in target
hit* hit_exists(target* t, u_char proto, u_short port, u_short icmp_type) {
    if(proto == IPPROTO_TCP)
        return hit_exists_in_list(t->tcp, port);
    if(proto == IPPROTO_UDP)
        return hit_exists_in_list(t->udp, port);
    if(proto == IPPROTO_ICMP)
        return hit_exists_in_list(t->icmp, icmp_type);
   return NULL; 
}

// does target ip exist in linked list
target* target_exists(target* t, char* ip) {
    while(t != NULL) {
        if(strcmp(t->ip, ip) == 0)
            return t;
        t = t->next;
    }
    return NULL;
} 

// create target
target* create_target(flow_pkt* pkt) {
    target* t = malloc(sizeof(target));
    strcpy(t->ip, pkt->ip_dst);
    t->tcp = NULL;
    t->udp = NULL;
    t->icmp = NULL;
    t->next = NULL;
    return t;
}

// add target to linked list
target* add_target_to_list(target** list, target* t) {
    target* tmp;
    if(*list == NULL) {
       *list = t;
    } else {
        tmp = *list;
        while(tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = t;
    }
    return *list;
}

// has scanner scanned this port on any target
int port_has_been_scanned(target* t, int proto, int port) {
    while(t != NULL) {
        if(proto == IPPROTO_TCP)
            if(hit_exists_in_list(t->tcp, port) != NULL)
                return 1;
        if(proto == IPPROTO_UDP)
            if(hit_exists_in_list(t->udp, port) != NULL)
                return 1;;
        if(proto == IPPROTO_ICMP) // do not increment port for icmp hits
            return 1;
        t = t->next;
    }
    return 0;
}


// update scanner
scanner* update_existing_scanner(scanner* s, flow_pkt* pkt_data) {
    target* t;
    hit* h;
    // target exists
    if ((t = target_exists(s->targets, pkt_data->ip_dst)) != NULL) {
        // target port/icmp hit already exists
        if((h = hit_exists(t, pkt_data->proto, pkt_data->dst_port, pkt_data->icmp_type)) != NULL) {
            // update hit
            update_hit(h, pkt_data);      
        // port does not exist
        } else {
            // add hit
            if(port_has_been_scanned(s->targets, pkt_data->proto, pkt_data->dst_port) == 0)
                s->ports_scanned++;
            h = create_hit(pkt_data);
            add_hit_to_target(t, h, pkt_data->proto);
        }
    // target does not exist
    } else {
        // add target and hit
        s->hosts_scanned++;
        if(port_has_been_scanned(s->targets, pkt_data->proto, pkt_data->dst_port) == 0)
            s->ports_scanned++;
        t = create_target(pkt_data);
        h = create_hit(pkt_data);
        add_hit_to_target(t, h, pkt_data->proto);
        add_target_to_list(&s->targets, t);
    }
    return s;
}

// remove scanner from linked list
scanner* scanner_list_rmv(scanner** list, scanner* s) {
    // node is in middle of list
    if(s->prev != NULL && s->next != NULL) {
        s->next->prev = s->prev;
        s->prev->next = s->next;
    // node is only item in list
    } else if(s->prev == NULL && s->next == NULL) {
        *list = NULL;
    // node is last item in list
    } else if(s->next == NULL) {
        s->prev->next = NULL;
    // node is first item in list
    } else if(s->prev == NULL) {
        s->next->prev = NULL;
        *list = s->next;
    }
    s->prev = NULL;
    s->next = NULL;
    return s;
}

// add scanner to link list
scanner* scanner_list_add(scanner** list, scanner* s) {
    scanner* tmp;
    if(*list == NULL) {
       *list = s;
    } else {
        tmp = *list;
        while(tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = s;
        s->prev = tmp;
    }
    return s;
}

// does scanner exist in linked list
scanner* exists_in_scanners(scanner* list, flow_pkt* pkt_data) {
    scanner* s = list;
    while(s != NULL) {
        if(strcmp(s->ip, pkt_data->ip_src) == 0) 
            return s;
        s = s->next;
    }
    return NULL;
}

// export scanner
scanner* export_scanner(scanner* s) {
    scanner_list_rmv(&_act_scan_list, s);
    scanner_list_add(&_exp_scan_list, s);
    return s;
}

// timeout scanner
int timeout_scanner(scanner* s, flow_pkt* pkt_data) {
    struct timeval temp; 
    temp.tv_sec = pkt_data->ts.tv_sec - s->start.tv_sec; // new duration in seconds
    temp.tv_usec = pkt_data->ts.tv_usec - s->start.tv_usec;
    if(pkt_data->ts.tv_usec < s->start.tv_usec) {
        temp.tv_sec -= 1;
        temp.tv_usec += 1000000;
    }
    if((temp.tv_sec > _timeout) || (temp.tv_sec == _timeout && temp.tv_usec > 0)) {
        export_scanner(s);
        return 1;
    }
    return 0;
}

// add a new scanner to linked list
scanner* add_new_scanner(flow_pkt* pkt) {
    hit* h;
    target* t;
    scanner* s = malloc(sizeof(scanner));
    strcpy(s->ip, pkt->ip_src); // ip of host doing scan
    s->start = pkt->ts;
    s->hosts_scanned = 1;
    s->ports_scanned = 0;
    if(pkt->proto != IPPROTO_ICMP) // dont log icmp
        s->ports_scanned++;
    s->targets = NULL;
    s->next = NULL;
    s->prev = NULL;
    t = create_target(pkt);
    h = create_hit(pkt);
    add_hit_to_target(t, h, pkt->proto);
    add_target_to_list(&s->targets, t);
    scanner_list_add(&_act_scan_list, s);
    return s;
}

// update scanners linked list
scanner* update_scanner(flow_pkt* pkt_data) {
    scanner* s;
    if((s = exists_in_scanners(_act_scan_list, pkt_data)) != NULL) 
        if(timeout_scanner(s, pkt_data) == 0) 
           return update_existing_scanner(s, pkt_data);
    return add_new_scanner(pkt_data); 
}

// create tcp packet struct from buffer and print data. 
void process_tcp(const u_char *packet, flow_pkt* pkt_data) {
    
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
   
    update_scanner(pkt_data);
    //update_flows(pkt_data);
  
    return;

}

// create udp packet struct from buffer and print data
void process_udp(const u_char *packet, flow_pkt* pkt_data) {

    const struct sniff_udp *udp_pkt;
    
    udp_pkt = (struct sniff_udp*) packet;
    
    pkt_data->src_port = ntohs(udp_pkt->uh_sport); 
    pkt_data->dst_port = ntohs(udp_pkt->uh_dport);
    strcpy(pkt_data->state, "");
    //printf("Source Port: %d\n", ntohs(udp_pkt->uh_sport));
    //printf("Destination Port: %d\n", ntohs(udp_pkt->uh_dport));
  
    //update_flows(pkt_data);
    update_scanner(pkt_data);

    return;

}

// create icmp packet struct from buffer and print data
void process_icmp(const u_char *packet, flow_pkt* pkt_data) {

    const struct sniff_icmp *icmp_pkt;
    
    icmp_pkt = (struct sniff_icmp*) packet;
   
    pkt_data->src_port = 0; 
    pkt_data->dst_port = 0;
    pkt_data->icmp_type = icmp_pkt->ih_type;
    //snprintf(pkt_data->state, STATE_LEN, "%d", icmp_pkt->ih_type);
    //printf("Type: %d\n", icmp_pkt->ih_type);
    //printf("Code: %d\n", icmp_pkt->ih_code);
    
    //update_flows(pkt_data);
    update_scanner(pkt_data);
    
    return;

}

// parse raw packet, this is function passed to pcap_loop()
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
    //static int count = 1;
    static int first = 0;
    static time_t start = 0;
    static time_t end = 0;
    time_offset* to;
    const struct sniff_ethernet *eth_pkt;
    const struct sniff_ip *ip_pkt;
    int size_ip;
    flow_pkt pkt_data;
    
    if(first == 0) {
        to = (time_offset*) args;
        start = header->ts.tv_sec + to->offset;
        end = header->ts.tv_sec + to->time; 
        first = 1;
    }  
     
    if(header->ts.tv_sec > end)
        pcap_breakloop(_handle);

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
	        process_tcp(packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } else if (ip_pkt->ip_p == IPPROTO_UDP) {
	        //puts("Protocol: UDP");
	        process_udp(packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } else if (ip_pkt->ip_p == IPPROTO_ICMP) {
	        //puts("Protcol: ICMP");
	        process_icmp(packet + SIZE_ETHERNET + size_ip, &pkt_data);
        } 
 
    }

    return;

}

// print usage message and exit
void usage(char* msg) {
    
    puts("Usage:\nfscan [-r filename] [-i interface] [-t time] [-o time_offset] [-S secs] [-h host threshold] [-p port threshold] [-V verbose]");
    printf("%s\n", msg);
    exit(1);

}

// get and set command line options.  Return type of file to sniff, live or offline
int get_options(int argc, char* argv[], char* dev, int* time, int* time_offset, 
                int* secs, int* hosts, int* ports, int* verbose) {

    // command line options parsing
    extern char *optarg;
    extern int optind;
    int rflag = 0;
    int iflag = 0;
    int tflag = 0;
    int oflag = 0;
    int sflag = 0;
    int hflag = 0;
    int pflag = 0;
    int vflag = 0;
    int c;

    //*time_offset = -1;

    while ((c= getopt(argc, argv, "r:i:t:o:S:h:p:V")) != EOF) {
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
            case 'S':
                sflag = 1;
                *secs = atoi(optarg);
                break;
            case 'h':
                hflag = 1;
                *hosts = atoi(optarg);
                break;
            case 'p':
                pflag = 1;
                *ports = atoi(optarg);
                break;
            case 'V':
                vflag = 1;
                *verbose = 1;
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

    pcap_breakloop(_handle);

}

// Open file for offline packet sniffing
void capture(int file_or_dev, char *dev, int t, int o) {
    
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string 
    bpf_u_int32 mask = 0; // netmask 
    bpf_u_int32 net = 0; // IP 
    struct bpf_program fp; // compiled filter 
    char filter_exp[] = "ip"; // filter expression 

    time_offset to;
    to.time = t;
    to.offset = o;

    if(file_or_dev == LIVE) {
       
        /* Find the properties for the device */
        if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }

        /* Open the session in promiscuous mode */
        _handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(_handle == NULL) {
            printf("Couldn't open device %s: %s\n", dev, errbuf);
            exit(1);
        }
      
        // end live sniffing after alarm signal
        signal(SIGALRM, catch_alarm);
        alarm(t);

    } else {

        /* Open file */
        _handle = pcap_open_offline(dev, errbuf);
        if(_handle == NULL) {
            printf("Couldn't open file %s: %s\n", dev, errbuf);
            exit(1);
        }

    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(_handle) != DLT_EN10MB) {
        printf("%s is not an Ethernet\n", dev);
        exit(1);
    }

    /* Compile and apply the filter */
    if(pcap_compile(_handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(_handle));
        exit(1);
    }
	
    if(pcap_setfilter(_handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(_handle));
	exit(1);
    }

    pcap_freecode(&fp);
    pcap_loop(_handle, 0, process_packet, (u_char*) &to);
 
    return;

}

int main(int argc, char *argv[]) {
    int file_or_dev; // read from file or device
    char dev[255];  // device to sniff on or file to process
    int t = 60; // time to run packet capture for
    int o = 0; // time to start packet capture for files 
    int S = 60; // max duration of a flow
    int h = 10; // host scan threshold
    int p = 6; // port scan threshold
    int V = 0; // verbose output
    // get the file or interface and set time parameters
    file_or_dev = get_options(argc, argv, dev, &t, &o, &S, &h, &p, &V);
    _act_scan_list = NULL;
    _exp_scan_list = NULL;
    _timeout = S;
    _hosts = h;
    _ports = p;
    capture(file_or_dev, dev, t, o);
    if(V == 1)
        print_scanners_detail();
    print_scanners_summary();
    pcap_close(_handle);
    return 0;
 }

