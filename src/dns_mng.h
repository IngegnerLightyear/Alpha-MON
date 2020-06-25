//
//  dns_mng.h
//  
//
//  Created by Thomas Favale on 08/11/2019.
//

#ifndef dns_mng_h
#define dns_mng_h
//#include "proto_mng.h"
//Header Files
#include<stdio.h> //printf
#include<string.h>    //strlen
#include<stdlib.h>    //malloc
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include <unistd.h>    //getpid
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_version.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <ldns/ldns.h>
#include "hash_calculator.h"

//Types of DNS resource records :)
 
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

/*typedef struct ret_info
{
    char * offset;
    size_t strLen;
} ret_info;*/

//DNS header structure
typedef struct dns_header
{    
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} dns_header;
 
//Constant sized fields of query structure
typedef struct question
{
    unsigned short qtype;
    unsigned short qclass;
} question;
 
//Constant sized fields of the resource record structure
typedef struct r_data
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} r_data;

//Pointers to resource record contents
typedef struct res_record
{
    unsigned char *name;
    r_data *resource;
    //unsigned char *rdata;
    unsigned char rdata[200];
} res_record;
 
//Structure of a Query
typedef struct query
{
    unsigned char *name;
    question *ques;
} query;

//Functions
dns_header * dns_header_extractor (struct rte_mbuf * , int , struct ipv4_hdr *, struct ipv6_hdr *);
size_t offset_extractor (int, struct ipv4_hdr *, struct ipv6_hdr *);
/* u_char* void*/ int  ReadName(unsigned char* ,unsigned char* ,int* );


#endif /* dns_mng_h */
