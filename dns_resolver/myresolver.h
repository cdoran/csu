// Charles Doran
// CS 457
// Fall 2014
// Project 3

// DNS Rsource Record Settings
#define A 1
#define AAAA 28
#define CNAME 5
#define NS 2
#define RRSIG 46
#define DNSKEY 48
#define SOA 6
#define OPT 41

// Project specific settings
#define IP4_BYTE_STR_LEN 4 // The size of an IP4 address in bytes
#define IP6_BYTE_STR_LEN 16  // The size of an IP6 address in bytes
#define IP6_ADDR_ARRAY_LEN 8 // The size of an IP6 address as a 16 bit int array 

#define ROOT_SERVERS_LEN  13 // The number of root servers we start with and max limit for iterative requests
#define PACKET_LEN 4096 // The maximum packet length we can handle
#define DNS_PORT 53
#define MAX_QNAME_LEN 256 // The maximum length of a domain name or qname 
#define MAX_RDATA_LEN 2048 // The maximum length of a RR rdata string
#define RR_ARRAY_LEN 64 // The maximum number of RR that may exist in an Answer, Authority or Additional sections 
#define GET_RRSIG 1 // send DNSSEC OPT RR with queries, 1=send, 0=dont send 
#define PRINT_RESPONSES 0 // print out all data for each iterative query

// flags struct for DNS header
typedef struct {
    char qr;
    char opcode;
    char aa;
    char tc;
    char rd;
    char ra;
    char z;
    char rcode;
} flags;

// DNS header struct
typedef struct {
    uint16_t id;
    flags f;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} header;

// DNS question struct.  We can only ask 1
typedef struct {
    char qname[MAX_QNAME_LEN];
    uint16_t qtype;
    uint16_t qclass;
} question;

// DNS Answer, Authority and Additional RRs 
typedef struct {
    char name[MAX_QNAME_LEN];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char rdata[MAX_RDATA_LEN];
} rr;

// DNS response structure
typedef struct {
    header h;
    question ques;
    rr ans[RR_ARRAY_LEN];
    rr auth[RR_ARRAY_LEN];
    rr add[RR_ARRAY_LEN];
} response;

// Root DNS servers for first  iteration of  queries
char* ROOT_SERVERS[]={"198.41.0.4", "192.228.79.201", "192.33.4.12", 
                      "199.7.91.13", "192.203.230.10", "192.5.5.241", 
                      "192.112.36.4" , "128.63.2.53","192.36.148.17", 
                      "192.58.128.30", "193.0.14.129", "199.7.83.42", 
                      "202.12.27.33"};


