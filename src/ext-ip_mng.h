//
//  ext-ip_mng.h
//  a-mon
//
//  Created by Thomas Favale on 13/10/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#ifndef ext_ip_mng_h
#define ext_ip_mng_h

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //malloc
#include <unistd.h>    //getpid

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lcore.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "proto_mng.h"

int external_ip (struct rte_mbuf *, struct timespec, int, struct table_flow *,hash_struct *, flow, int, int);
uint32_t addressV4_gen();
void addressV6_gen(struct in6_addr *);


#endif /* ext_ip_mng_h */
