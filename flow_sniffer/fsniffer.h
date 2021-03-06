/* Charles Doran
   CS 557 
   HW2

   The structs sniff_ethernet, sniff_ip, sniff_tcp, and typedef tcp_seq 
   and Ethernet size constants were taken from the tutorial at 
   http://www.tcpdump.org/pcap.html 

*/

/* some proper names for flags */
#define OFFLINE 0
#define LIVE 1 

#define ARRAY_BLOCK 50
#define DIR_SRC_DST 0
#define DIR_DST_SRC 1
#define DIR_BOTH 2
#define DIR_UNKNOWN 3
#define STATE_LEN 10
#define IP_ADDR_LEN 16

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		    /* version << 4 | header length >> 2 */
	u_char ip_tos;		    /* type of service */
	u_short ip_len;		    /* total length */
	u_short ip_id;		    /* identification */
	u_short ip_off;		    /* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		          /* time to live */
	u_char ip_p;		          /* protocol */
	u_short ip_sum;		          /* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* UDP header */
struct sniff_udp {
        u_short uh_sport;
        u_short uh_dport;
        u_short uh_len;
        u_short uh_sum;
};

/* ICMP header */
struct sniff_icmp {
        u_char ih_type;
        u_char ih_code;
        u_short ih_sum;
        bpf_u_int32 ih_extra; 
};

// Data we need from each packet processed, added to a flow
typedef struct {
    struct timeval ts;
    bpf_u_int32 len;
    u_char proto; 
    char ip_src[IP_ADDR_LEN];
    char ip_dst[IP_ADDR_LEN];
    u_short src_port;
    u_short dst_port;
    char state[STATE_LEN];
} flow_pkt;

// represents a flow
typedef struct {
    struct timeval start;
    u_char proto;
 	char ip_src[IP_ADDR_LEN];
    char ip_dst[IP_ADDR_LEN];
    u_short src_port;
    u_short dst_port;
    u_char dir;
    int tot_pkts;
    int tot_bytes;
    char state[STATE_LEN];
    struct timeval dur;   
} flow;

//  An array to hold all flows, data to manage array, and program parameters
typedef struct {
    pcap_t* handle; // reference to handle so we can terminate 
    flow* flows; // array to keep track of each flow
    int flows_len; // length of flows array
    int capacity;  // size of allocated memory for array
    int time; // time the program should run for
    int offset; // offset, to start reading pcap file packets
    int timeout; // max duration of a flow
    int records; // max number of records to print out
    int exported; // number of records that have been written to terminal
} flow_mngr;
