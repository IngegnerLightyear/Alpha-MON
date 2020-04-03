#ifndef PROTO_MNG_H
#define PROTO_MNG_H

#include <rte_hash.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <sys/time.h>
#include <time.h>
#include <rte_malloc.h>

//#include "traffic_anon.h"


//#include "hash_calculator.h"
#include <unistd.h>    //getpid
#include "dns_mng.h"
#include "tls_mng.h"
#include "traffic_anon.h"
#include "hash_calculator.h"
#include "process_packet.h"

/* Protocol Type */
#define TCP             0x06
#define UDP    	        0x11

/* Protocol Port */
#define FTP_DATA	20
#define FTP_CONTROL 	21
#define SSH 		22
#define HTTP 		80
#define HTTPS 		443
#define DNS 		53

#define MAX_CLIENT 900
#define FLOW_TABLE_SIZE 10000//900
#define NAME_DNS 500

#define DEBUG 1

/* Types */

typedef struct ret_info
{
    char * offset;
    char *name;
    size_t strLen;
} ret_info;

struct lru
{
    int full;
    int client_hash;
    time_t timestamp;
    struct lru *prev;
    struct lru *next;
} lru;

typedef struct client
{
    int active;
    int ipv;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    __uint128_t ipv6_src;
    __uint128_t ipv6_dst;
    uint16_t in_port;
    uint16_t out_port;
    uint8_t  protocol;
    time_t last_seen;
    struct lru *lru_ptr;
} client;

struct names
{
    int full;
    char name[NAME_DNS];
    //char anon_name[100];
    int n_entry;
    int n_client;
    time_t oldest;
    struct names *prev;
    struct names *next;
    struct lru *head;
    struct lru *tail;
    client client_list[MAX_CLIENT];
} names;

typedef struct hash_struct
{
        int *bitMap;//[FLOW_TABLE_SIZE];
        struct names *table;//[FLOW_TABLE_SIZE];
} hash_struct;

typedef struct flow
{
    int ipv;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    __uint128_t ipv6_src;
    __uint128_t ipv6_dst;
    uint16_t in_port;
    uint16_t out_port;
    uint8_t  protocol;
    time_t timestamp;
} flow;



/* Variables */
hash_struct flow_db[MAX_CORES];


/* Functions for protocols */
void proto_init(int nb_sys_cores);
void multiplexer_proto(struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, struct rte_mbuf * packet, int core, struct timespec tp, int id, out_interface_sett, crypto_ip *);
void dnsEntry (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, flow newPacket, hash_struct *flow_db, int k_anon, int k_delta, crypto_ip *, int, int);
void remove_dnsquery_name (char * buff);
void remove_dns_name (struct rte_mbuf * packet, ret_info info);
void remove_payload(struct rte_mbuf * packet, size_t offset);

/* Table Functions */
void table_init(hash_struct *);
int table_add(hash_struct *flow_db, flow flow_recv, char * name, int k_anon, int k_delta);



#endif //PROTO_MNG_H


