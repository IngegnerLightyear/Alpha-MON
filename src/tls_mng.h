//
//  tls_mng.h
//  a-mon
//
//  Created by Thomas Favale on 19/03/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#ifndef tls_mng_h
#define tls_mng_h

#include <stdio.h>
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


//TLS version numbers
#define SSL_VERSION_3_0 0x0300
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304


/*typedef struct tls_header_v1
{
    unsigned char rt; // record type 0x16 for "records contains some handshake message data"
    unsigned short id; // protocol version 0x03 0x00 for SSL 3.0, 0x03 0x01 for TLS 1.0, and so on
    unsigned short rl; // record length big endian
    unsigned char ht; // handshake type (client hello 0x01)
} tls_header_v1;*/

typedef struct tls_header_v2
{
    /*uint8_t rt; // record type 0x16 for "records contains some handshake message data"
    uint16_t protv; // protocol version 0x03 0x00 for SSL 3.0, 0x03 0x01 for TLS 1.0, and so on
    uint16_t rl; // record length big endian
    uint8_t ht; // handshake type (client hello 0x01)
    uint8_t hl1; //bytes of client hello follows
    uint8_t hl2;
    uint8_t hl3;
    uint16_t c_ver; //client version*/
    unsigned char rt;
    unsigned char protv1;
    unsigned char protv2;
    unsigned char rl1;
    unsigned char rl2;
    //unsigned short protv; // protocol version 0x03 0x00 for SSL 3.0, 0x03 0x01 for TLS 1.0, and so on
    //unsigned short rl; // record length big endian
    unsigned char ht; // handshake type (client hello 0x01)
    unsigned char hl1; //bytes of client hello follows
    unsigned char hl2;
    unsigned char hl3;
    unsigned short c_ver;
    
} tls_header_v2;

typedef struct tls_header_v0
{
    char val[12];
} tls_header_v0;

tls_header_v2 * tls_header_extractor (struct rte_mbuf *, int, struct ipv4_hdr *, struct ipv6_hdr *);
size_t offset_extractor_tls (int, struct ipv4_hdr *, struct ipv6_hdr *);

#endif /* tls_mng_h */
