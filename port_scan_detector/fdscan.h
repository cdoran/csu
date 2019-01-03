/* Charles Doran
   CS 557 
   HW3

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

/* struct for passing time offset  info to pcap_loop callback */
typedef struct {
    int time;
    int offset;
} time_offset;

typedef struct {
    struct timeval ts;
    bpf_u_int32 len;
    u_char proto; 
    char ip_src[IP_ADDR_LEN];
    char ip_dst[IP_ADDR_LEN];
    u_short src_port;
    u_short dst_port;
    char state[STATE_LEN];
    u_short icmp_type;
} flow_pkt;

typedef struct flow {
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
    struct flow* next;
    struct flow* prev;
} flow;

typedef struct hit  {
    u_short num; // port number or icmp type
    struct timeval t; // last timestamp
    int pkts; // number of pkts
    int bytes; // number of bytes
    struct hit* next; 
} hit;

typedef struct target {
    char ip[IP_ADDR_LEN]; // ip of host that was scanned
    hit* udp;
    hit* tcp;
    hit* icmp;
    struct target* next; // next scanned
} target;

typedef struct scanner {
    char ip[IP_ADDR_LEN]; // ip of host doing scan
    struct timeval start;
    int hosts_scanned;
    int ports_scanned;
    target* targets;
    struct scanner* next;
    struct scanner* prev;
} scanner;

