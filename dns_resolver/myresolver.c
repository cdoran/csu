// Charles Doran
// CS 457
// Fall 2014
// Project 3

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include "myresolver.h"

// set initial query id. Value is incremented for each query iteration   
uint16_t query_count = 538; 

// handle errors in one line
void error(char const *msg) {
	fprintf(stderr, "%s: %s\n", msg, strerror(errno));
	exit(1);
}

// print packet in hex for debugging
void packet_print_raw(char *buf, int len) {
	int i;
	for(i = 0; i < len; i++)
		printf("%02hhX ", buf[i]);
	printf("\n\n");
	return;
}

// convert a resource record type string to int value 
int get_type(char* type) {
    if(strcmp(type, "AAAA") == 0)
        return AAAA;
    if(strcmp(type, "A") == 0)
        return A;
    if(strcmp(type, "CNAME") == 0)
        return CNAME;
    if(strcmp(type, "RRSIG") == 0)
        return RRSIG;
    if(strcmp(type, "NS") == 0)
        return NS;
    if(strcmp(type, "SOA") == 0)
        return SOA; 
    if(strcmp(type, "OPT") == 0)
        return OPT;
    if(strcmp(type, "DNSKEY") == 0)
        return DNSKEY;
    return -1;
}

// convert a resource record int value to a string
char* get_type_str(int type) {
    if(type == A)
        return "A";
    if(type == NS)
        return "NS";
    if(type == CNAME)
        return "CNAME";
    if(type == RRSIG)
        return "RRSIG";
    if(type == AAAA)
        return "AAAA";
    if(type == SOA)
        return "SOA";
    if(type == DNSKEY)
        return "DNSKEY";
    if(type == OPT)
        return "OPT";
    return "";
}

// return class type as string.  We only deal with IN
char* get_class_str(int class) {
    if(class == 1)
        return "IN";
    return "";
}

// convert 4 byte array to IP4 formatted c string.
int ip4_format(char* byte_str, char* ip_addr) {
    int i;
    int ia_len = 0;
    for(i=0; i<IP4_BYTE_STR_LEN; i++) {
        ia_len = snprintf(ip_addr + ia_len, 4, "%hhu", byte_str[i]);
        if(i < IP4_BYTE_STR_LEN - 1)
            strcat(ip_addr, ".");
        ia_len = strlen(ip_addr);
    }
    return ia_len;
}

// convert 16 byte array to IP6 formatted c string.
int ip6_format(char* byte_str, char* ip_addr_str) {
    int i;
    uint16_t ip_addr_x[IP6_ADDR_ARRAY_LEN]; // IP6 address array
    int ip_addr_str_len = 0; // length of ip_addr_str 
    memcpy(&ip_addr_x, byte_str, IP6_BYTE_STR_LEN);
    for(i=0; i<IP6_ADDR_ARRAY_LEN; i++) {
        ip_addr_x[i] = ntohs(ip_addr_x[i]);
        ip_addr_str_len = snprintf(ip_addr_str + ip_addr_str_len, 5, "%X", ip_addr_x[i]);
        if(i < IP6_ADDR_ARRAY_LEN - 1)
            strcat(ip_addr_str, ":");
        ip_addr_str_len = strlen(ip_addr_str);
    }
    return ip_addr_str_len;
}

// convert byte string to hex c string
int hex_string_format(char* buf, char* rdata, int rdlength) {
    int i;
    if(rdlength == 0)
        rdata[0] = 0;
    for(i=0; i<rdlength; i++) {
        if(i >= MAX_RDATA_LEN)
            break;
        sprintf(rdata + i*3, "%02hhX ", buf[i]);
    }
    return strlen(rdata);
}

// convert qname to domain name, return length of qname including null byte 
int domain_name_format(char* buf, char* qname, char* domain_name) {
    int q = 0; // index for qname
    int d = 0; // index for domain_name
    uint16_t offset;
    while(1) {
        if(qname[q] == 0) 
            break;
        if((unsigned char) qname[q] >= 0xC0) {
            memcpy(&offset, qname + q, 2);
            offset = ntohs(offset);
            offset = offset & 0x03FF;
            domain_name_format(buf, buf + offset, domain_name + d);
            return q + 2;
        }
        strncpy(domain_name + d, qname + q + 1, (size_t) qname[q]);
        d += qname[q]; 
        domain_name[d++] = '.';
        q += qname[q] + 1;
    }
    domain_name[d] = '\0'; //domain_name[d-1] = '\0';
    return strlen(qname) + 1;
    
}

// convert domain name to qname format, return length qname 
int qname_format(const char* domain_name, char* qname) {
    char tmp_domain_name[MAX_QNAME_LEN];
	char* d;
	char d_len; 
	int total_len = 0;	
    strcpy(tmp_domain_name, domain_name);
	d = strtok(tmp_domain_name, ".");
	while(d != NULL) {
		d_len = (char) strlen(d);
		if((total_len + d_len + 2) > MAX_QNAME_LEN) // +2, 1 terminating byte and 1 byte for d len 
			error("domain name to qname format exceeds maximum limit");
		memcpy(qname + total_len++, &d_len, 1);
		strncpy(qname + total_len, d, d_len);  
		total_len += d_len;
		d = strtok(NULL, ".");
	}	
	d_len = 0;
	memcpy(qname + total_len++, &d_len, 1);
	return total_len;
}

// format rdata for RRSIG RR.  Converts signature to Hex byte string, not Base64.
int rrsig_format(char* byte_str, char* result, int byte_str_len) {
    int l;
    char tmp_str[MAX_RDATA_LEN] = {0}; 
    char tmp8;
    uint16_t tmp16;
    uint32_t tmp32;
    memcpy(&tmp16, byte_str, 2);
    sprintf(result, "%s", get_type_str(ntohs(tmp16)));
    memcpy(&tmp8, byte_str+2, 1);
    sprintf(tmp_str, " %d", tmp8);
    strcat(result, tmp_str);
    memcpy(&tmp8, byte_str+3, 1);
    sprintf(tmp_str, " %d", tmp8);
    strcat(result, tmp_str);
    memcpy(&tmp32, byte_str+4, 4);
    sprintf(tmp_str, " %d", ntohl(tmp32));
    strcat(result, tmp_str);
    memcpy(&tmp32, byte_str+8, 4);
    sprintf(tmp_str, " %d", ntohl(tmp32));
    strcat(result, tmp_str);
    memcpy(&tmp32, byte_str+12, 4);
    sprintf(tmp_str, " %d", ntohl(tmp32));
    strcat(result, tmp_str);
    memcpy(&tmp16, byte_str+16, 2);
    sprintf(tmp_str, " %d ", ntohs(tmp16));
    strcat(result, tmp_str);
    l = domain_name_format(byte_str+18, byte_str+18, tmp_str);
    strcat(result, tmp_str); 
    strcat(result, " ");
    l += 18;
    hex_string_format(byte_str+l, tmp_str, byte_str_len-l); 
    strcat(result, tmp_str); 
    return strlen(result);
}
 
// set flags structure from 16 bit raw flags value 
void set_flags(uint16_t flags_raw, flags* f) {
    uint16_t cmp = 32768;
    f->qr = (char) ((flags_raw & cmp) >> 15);
    cmp = 16384 + 8192 + 4096 + 2048;
    f->opcode = (char) ((flags_raw & cmp) >> 11);
    cmp = 1024;
    f->aa = (char) ((flags_raw & cmp) >> 10);
    cmp = 512;
    f->tc = (char) ((flags_raw & cmp) >> 9);
    cmp = 256;
    f->rd = (char) ((flags_raw & cmp) >> 8);
    cmp = 128;
    f->ra = (char) ((flags_raw & cmp) >> 7);
    cmp = 64 + 32 + 16;
    f->z = (char) ((flags_raw & cmp) >> 4);
    cmp = 8 + 4 + 2 + 1;
    f->rcode = (char) (flags_raw & cmp);
    return;
}

// print dns packer header values 
void print_header(header h) {
    printf("id: %d  qdcount: %d  ancount: %d  nscount: %d  arcount: %d\n",
            h.id, h.qdcount, h.ancount, h.nscount, h.arcount); 
    printf("FLAGS\tqr: %d  opcode: %d  aa: %d  tc: %d  rd: %d  ra: %d  z: %d  rcode: %d\n", 
            h.f.qr, h.f.opcode, h.f.aa, h.f.tc, h.f.rd, h.f.ra, h.f.z, h.f.rcode);
    return;
}

// print  question structure to console
void print_ques(question q) {
    printf("%-25s %-5s %-5s\n", "qname", "qtype", "qclass");
    printf("%-25s %-5s %-5s\n", q.qname, get_type_str(q.qtype), get_class_str(q.qclass));
    return;
}

// print resource record structure to console
void print_rr(rr r) {
    if(r.class == 1) // class == IN
        printf("%-25s %-10d %-10s %-10s %-10s\n", r.name, r.ttl, get_type_str(r.type), get_class_str(r.class), r.rdata); 
    else // or we have an OPT RR
         printf("%-25s %-10d %-10s %-10d %-10s\n", r.name, r.ttl, get_type_str(r.type), r.class, r.rdata);
    return;
}

// remove print_answer() from print_response() below so we can output per project specs
void print_answer(response *r) {
    int i;
    printf("%-25s %-10s %-10s %-10s %-10s\n", "name", "ttl", "type", "class", "data");
    for(i=0; i<r->h.ancount; i++)
        print_rr(r->ans[i]);
    puts("");
}

// print dns server response sturcture to console
void print_response(response* r) {
    int i;
    puts("================ HEADER ================");
    print_header(r->h);
    puts("");
    puts("=============== QUESTION ===============");
    if(r->h.qdcount == 1)
        print_ques(r->ques); 
    puts("");
    puts("================ ANSWER ================");
    print_answer(r);
    puts("=============== AUTHORITY ==============");
    printf("%-25s %-10s %-10s %-10s %-10s\n", "name", "ttl", "type", "class", "data");
    for(i=0; i<r->h.nscount; i++)
        print_rr(r->auth[i]);
    puts("");
    puts("============== ADDITIONAL ==============");
    printf("%-25s %-10s %-10s %-10s %-10s\n", "name", "ttl", "type", "class", "data");
    for(i=0; i<r->h.arcount; i++)
        print_rr(r->add[i]);
    puts("");
    return;
}

//create dns query packet in buf from given domain name and query type 
int packet_send(const char *domain_name, int type, char *buf) {
    // set header 
	uint16_t id = htons(query_count++);
	uint16_t flags = 0;
	uint16_t qdcount = htons(1);
	uint16_t ancount = 0;
	uint16_t nscount = 0;
	uint16_t arcount = 0;
    // set question RR
	char qname[MAX_QNAME_LEN];
	int qname_len = qname_format(domain_name, qname);
	uint16_t qtype = htons(type);
	uint16_t qclass = htons(1);
    // set additinal record with DNSSEC OPT RR
    char arname = 0;
    uint16_t artype = htons(OPT);
    uint16_t arclass = htons(PACKET_LEN);
    uint32_t arttl = htonl(32768); 
    uint16_t arrdlen = 0; // htons(1);
    // char arrdata = 0;
    // build packet
	if(GET_RRSIG)
        arcount = htons(1);
    memset(buf, 0, PACKET_LEN);
	memcpy(buf + 0, &id, 2);
	memcpy(buf + 2, &flags, 2);
	memcpy(buf + 4, &qdcount, 2);
	memcpy(buf + 6, &ancount, 2);
	memcpy(buf + 8, &nscount, 2);
	memcpy(buf + 10, &arcount, 2);
	memcpy(buf + 12, qname, qname_len);
	memcpy(buf + 12 + qname_len, &qtype, 2);
	memcpy(buf + 14 + qname_len, &qclass, 2);
    if(!GET_RRSIG)
	    return qname_len + 16;
	memcpy(buf + 16 + qname_len, &arname, 1);
	memcpy(buf + 17 + qname_len, &artype, 2);
	memcpy(buf + 19 + qname_len, &arclass, 2);
    memcpy(buf + 21 + qname_len, &arttl, 4);
    memcpy(buf + 25 + qname_len, &arrdlen, 2);
    //memcpy(buf + 28 + qname_len, &arrdata, 1);
    //packet_print_raw(buf, PACKET_LEN);
    return qname_len + 27;
}

// populate resource record structure from byte string
void process_rr(char* buf, int* offset, rr* r) {
    uint16_t tmp;
    uint32_t tmp32;
    *offset += domain_name_format(buf, buf + *offset, r->name);
    memcpy(&tmp, buf + *offset, 2);
    r->type = ntohs(tmp);
    *offset += 2;
	memcpy(&tmp, buf + *offset, 2);
    r->class = ntohs(tmp);
    *offset += 2;
	memcpy(&tmp32, buf + *offset, 4);
    r->ttl = ntohl(tmp32);
    *offset += 4;
    memcpy(&tmp, buf + *offset, 2);
    r->rdlength = ntohs(tmp); 
    *offset += 2;
    if(r->rdlength > MAX_RDATA_LEN)
        error("rdata response too long");
    if(r->type == A && r->rdlength == IP4_BYTE_STR_LEN)
        ip4_format(buf + *offset, r->rdata);
    else if(r->type == NS || r->type == CNAME)
        domain_name_format(buf, buf + *offset, r->rdata);
    else if(r->type == AAAA && r->rdlength == IP6_BYTE_STR_LEN)
        ip6_format(buf + *offset, r->rdata);
    else if(r->type == RRSIG)
        rrsig_format(buf + *offset, r->rdata, r->rdlength);
    else 
        hex_string_format(buf + *offset, r->rdata, r->rdlength);
    *offset += r->rdlength;
    return;
}

// populate question structure from byte string
void process_ques(char* buf, int* offset, question* q) {
    uint16_t tmp;
    *offset += domain_name_format(buf, buf + *offset, q->qname);
    memcpy(&tmp, buf + *offset, 2);
    q->qtype = ntohs(tmp);
    *offset += 2;
	memcpy(&tmp, buf + *offset, 2);
    q->qclass = ntohs(tmp);
    *offset += 2;
}

// populate header structure from byte string
void process_head(char* buf, int* offset, header* h) {
    uint16_t tmp;
    memcpy(&tmp, buf + *offset, 2);
    h->id = ntohs(tmp);
    *offset += 2;
    memcpy(&tmp, buf + *offset, 2);
    set_flags(ntohs(tmp), &(h->f));
    *offset += 2;
    memcpy(&tmp, buf + *offset, 2);
    h->qdcount = ntohs(tmp);
	*offset += 2;
    memcpy(&tmp, buf + *offset, 2);
    h->ancount = ntohs(tmp);
	*offset += 2;
    memcpy(&tmp, buf + *offset, 2);
	h->nscount = ntohs(tmp);
    *offset += 2;
    memcpy(&tmp, buf + *offset, 2);
    h->arcount = ntohs(tmp);
    *offset += 2;
    return;
}

// populate dns response structure from raw dns packet
void packet_recv(char* buf, response* r) {
    int i;
    int offset = 0;
    process_head(buf, &offset, &(r->h));
    if(r->h.qdcount == 1)
        process_ques(buf, &offset, &(r->ques));
    for(i=0; i<r->h.ancount; i++)
        process_rr(buf, &offset, &(r->ans[i]));
    for(i=0; i<r->h.nscount; i++)
        process_rr(buf, &offset, &(r->auth[i]));
    for(i=0; i<r->h.arcount; i++)
        process_rr(buf, &offset, &(r->add[i]));
    return;
}

// sometimes send() doesn't send everything so we do this
void send_all(int socket, char* buf) {
	int len_sent;
	int packet_len = PACKET_LEN;
  	while(packet_len > 0) {
		len_sent = send(socket, buf, packet_len, 0);
		if(len_sent < 0) //error 
			len_sent = 0;
			//return PACKET_LEN - packet_len;
		buf += len_sent;
		packet_len -= len_sent;
	}
	return;
}

// this dns client sends queries based on domain name and type and returns dns response struct
// params: dns_ips -  array of ip addresses as c strings
//         den_ips_len - length of server_ip
//         domain_name - domain name to query
//         type - type of resource record to query for, A or AAAA
response* dns_client(char** dns_ips, int dns_ips_len, const char* domain_name, int type) {
	int client_socket = 0;
	struct sockaddr_in server_address;	
    struct timeval t;
	unsigned int server_len;
	char buf[PACKET_LEN + 1] = {0};
    int buf_len;
	int result;
    int dns_ips_index = 0; 
    response* r;
    char* server_ip = dns_ips[dns_ips_index];
    r = (response*) malloc(sizeof(response));
    // set timeout value to 3.5 seconds
    t.tv_sec = 3;
    t.tv_usec = 500000;
    // set server socket address
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(DNS_PORT);
    	server_address.sin_addr.s_addr = inet_addr(server_ip);

	if((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		error("Cannot get socket");
    
    if(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) < 0)
        error("Cannot set socket receive timeout");

	buf_len = packet_send(domain_name, type, buf);
    //packet_print_raw(buf, buf_len);
    while(1) {    
        if(dns_ips_index == dns_ips_len) {
            close(client_socket);
            error("Cannot reach DNS servers. Exiting.");
        }
	    if ((result = sendto(client_socket, buf, buf_len, 0, (struct sockaddr *)&server_address, sizeof(server_address))) >  0 ) {
            	memset(buf, 0, PACKET_LEN);
	        if ((result = recvfrom(client_socket, buf, PACKET_LEN, MSG_WAITALL, (struct sockaddr *)&server_address, &server_len)) > 0) { 
			break; 
            } else {
                server_ip = dns_ips[++dns_ips_index];
                puts("Cannot receive... Trying next server.");
            }
        } else {
            server_ip = dns_ips[++dns_ips_index];
		    puts("Cannot send... Trying next server.");
	    }
    }	
    //packet_print_raw(buf, result);
    packet_recv(buf, r);
    close(client_socket);
    return r;
}

// get the list of DNS servers for the next iterative query
int get_next_dns_list(response* r, char** server_ip) {
    int i=0, j=0;
    if(r->h.arcount > 0) {
        for(i=0; i<r->h.arcount && i<ROOT_SERVERS_LEN; i++) 
            if(r->add[i].type == A)
                server_ip[j++] = r->add[i].rdata;
   }
   return j;
}

// Do we have the record we are looking for in the response answer
int ans_record_exists(int type, response* r) {
    int i;
    for(i=0; i<r->h.ancount; i++)
        if(r->ans[i].type == type)
            return 1;
    return 0;
}

// switch the domain name to last CNAME we have in response
void set_cname(char* domain_name, response* r) {
    int i;
    for(i=0; i<r->h.ancount; i++)
        if(r->ans[i].type == CNAME) {
            strcpy(domain_name, r->ans[i].rdata);
            return;
        }
    return;
}

// Make iterative queries unitl we have an answer or cannot go any further 
void find_record(char* domain_name, int type) {
    response* r;
    char** dns_ips;
    int dns_ips_len = ROOT_SERVERS_LEN;
    char* tmp_dns_ips[ROOT_SERVERS_LEN];
    dns_ips = ROOT_SERVERS;
    while(1) {
        r = dns_client(dns_ips, dns_ips_len, domain_name, type);
        dns_ips = tmp_dns_ips;
        dns_ips_len = get_next_dns_list(r, dns_ips);
        if(PRINT_RESPONSES)
            print_response(r);
        // NXDOMAIN
        if(r->h.f.rcode == 3) {
            printf("NXDOMAIN: %s does not exist\n", domain_name);
            break;
        }
        // Truncated Data
        if(r->h.f.tc == 1) {
            puts("Message truncated.  This resolver cannot switch to TCP. Exiting.");
            break;
        }
        // We have an answer
        if(r->h.ancount > 0) {
            // Do CNAME chase
            if(ans_record_exists(CNAME, r)) {
                if(!PRINT_RESPONSES)
                    print_answer(r);
                set_cname(domain_name, r);            
                dns_ips = ROOT_SERVERS;
                dns_ips_len = ROOT_SERVERS_LEN;
            // we have the record we are looking for
            } else if(ans_record_exists(type, r)) {
                if(!PRINT_RESPONSES)
                    print_answer(r);
                break;
            } 
        }
        //free(r);
        // we do not have another valid IP to ask
        if(dns_ips_len <= 0) {
            printf("No %s record exists for %s.\n", get_type_str(type), domain_name);
            break;
        }
    }
    return;
}

// Get input form console and run: find_record(domain_name, record_type)
// We are relying on perfectly formed input ie: ./myresolver <domain-name> [record-type]
int main(int argc, char* argv[]) {
    int type = A; 
    if(argc != 2 && argc != 3)
        error("Usage");
    if(argc == 3)
        type = get_type(argv[2]);
    find_record(argv[1], type);
    return 0;
}

