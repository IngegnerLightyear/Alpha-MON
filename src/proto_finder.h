//
//  proto_finder.h
//  a-mon
//
//  Created by Thomas Favale on 16/03/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#ifndef proto_finder_h
#define proto_finder_h

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
//#include "proto_mng.h"
#include "dns_mng.h"

/* Protocol Port */
#define FTP_DATA        20
#define FTP_CONTROL     21
#define SSH             22
#define HTTP            80
#define HTTPS           443
#define DNS             53




int proto_detector(struct rte_mbuf *, int, struct ipv4_hdr *, struct ipv6_hdr *, uint16_t , uint16_t);
int isDns(struct rte_mbuf *, int, struct ipv4_hdr *, struct ipv6_hdr *, uint16_t , uint16_t);
int isTls(struct rte_mbuf *, int, struct ipv4_hdr *, struct ipv6_hdr *, uint16_t , uint16_t);
#endif /* proto_finder_h */
