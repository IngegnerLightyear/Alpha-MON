//
//  http_mng.h
//  a-mon
//
//  Created by Thomas Favale on 06/07/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#ifndef http_mng_h
#define http_mng_h

#include <stdio.h>
#include <string.h>    //strlen
#include <stdlib.h>    //malloc
#include <unistd.h>    //getpid

#include "proto_mng.h"

char * http_header_extractor (struct rte_mbuf *, int, struct ipv4_hdr *, struct ipv6_hdr *);
size_t offset_extractor_http (int, struct ipv4_hdr *, struct ipv6_hdr *, uint8_t);




#endif /* http_mng_h */
