//
//  flow_mng.h
//  a-mon
//
//  Created by Thomas Favale on 26/06/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#ifndef flow_mng_h
#define flow_mng_h

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //malloc
#include <unistd.h>    //getpid

#include "proto_mng.h"

/* Protocol Type */
#define T_OUT             300
#define TCP_UDP_FLOWS     2000003

struct table_flow
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
    int toAnon;
    struct table_flow *prev;
    struct table_flow *next;
} table_flow;

typedef struct flow_mng
{
    struct table_flow *table;
    entry_access *bitMap;
} flow_mng;

flow_mng flow_struct;

void flow_table_init();
struct table_flow * reference_flow(flow *data);

#endif /* flow_mng_h */
