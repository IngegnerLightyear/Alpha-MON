//
//  proto_finder.c
//  a-mon
//
//  Created by Thomas Favale on 16/03/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#include "proto_finder.h"

//Protocol return code
//DNS = 53

int proto_detector(struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint16_t inport, uint16_t outport)
{
    if(isDns(packet, protocol, ipv4_header, ipv6_header, inport, outport)==0)
    {
        return 53;
    }
    /*else if(isTls(packet, protocol, ipv4_header, ipv6_header)==0)
        printf("TLS\n"); //todo*/
    else
    {
        return 0;
    }
}

int isDns(struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint16_t inport, uint16_t outport)
{
    dns_header *dns;
    dns = dns_header_extractor(packet, protocol, ipv4_header, ipv6_header);
    if(inport == 53 || outport == 53)
    {
        if(outport==53 && dns->qr!=0)
            return 1;//wrong question format
        if(inport==53 && dns->qr!=1)
            return 1;//wrong response format
        if((dns->z)!=0)
            return 1;//wrong Z value
        if(ntohs(dns->opcode)!=0 && ntohs(dns->opcode)!=1 && ntohs(dns->opcode)!=2 && ntohs(dns->opcode)!=4 && ntohs(dns->opcode)!=5)
            return 1;//wrong opcode value
        if((dns->aa)!=0 && (dns->aa)!=1)
            return 1;//wrong Authoritative Answer value
        if((dns->tc)!=0 && (dns->tc)!=1)
            return 1;//wrong TrunCation
        if((dns->rd)!=0 && (dns->rd)!=1)
            return 1;//wrong Recursion Desired value
        if((dns->ra)!=0 && (dns->ra)!=1)
            return 1;//wrong Recursion Available value
        return 0;
    }
    else
        return 1;
}


