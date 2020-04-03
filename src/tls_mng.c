//
//  tls_mng.c
//  a-mon
//
//  Created by Thomas Favale on 19/03/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#include "tls_mng.h"

tls_header_v2 * tls_header_extractor (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    return rte_pktmbuf_mtod_offset(packet, tls_header_v2*, offset_extractor_tls (protocol, ipv4_header, ipv6_header) );
}

size_t offset_extractor_tls (int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    if(ipv4_header!=NULL)
    {
        if(protocol == 0)
            return sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+sizeof(struct tcp_hdr)+12;//dpdk struct seems incomplete
        else if(protocol == 1)
            return sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
    else
    {
        if(protocol == 0)
            return sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+sizeof(struct tcp_hdr)+12;//dpdk struct seems incomplete
        else if(protocol == 1)
            return sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
}
