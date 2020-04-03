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
        return 53;
    else if(isTls(packet, protocol, ipv4_header, ipv6_header)==0)
    {
//        printf("TLS!!!\n");
         return 443;
    }
    else
        return 0;
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

int isTls(struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    if(ipv4_header!=NULL)
    {
        long *p, *o;
        struct in_addr addr, addr1;
        //p=(long*)ipv4_header->src_addr;
        //o=(long*)ipv4_header->dst_addr;
        addr.s_addr=(ipv4_header->src_addr); //working without ntohl
        addr1.s_addr=(ipv4_header->dst_addr);
//        printf("sIP = %s | dIP = %s\n", inet_ntoa(addr), inet_ntoa(addr1));
    }
    tls_header_v2 *tls_h;
    tls_h = tls_header_extractor(packet, protocol, ipv4_header, ipv6_header);
    
    /*for (int i=0; i<12; i++)
    {
        printf("%x|\n", tls_h->val[i]);
    }
    printf("\n");
    return 1;*/
    
    //printf("record type: 0x%02hhx|\n",tls_h->rt);
//    printf("record type: %u|\n",tls_h->rt);
//    printf("protocol version: %x|\n",tls_h->protv1);
//    printf("protocol version: %x|\n",tls_h->protv2);
//    printf("record length: %x|\n",ntohs(tls_h->rl1));
//    printf("record length: %x|\n",ntohs(tls_h->rl2));
//    printf("handshake type: %u|\n",tls_h->ht);
//    printf("header len1: %u|\n",tls_h->hl1);
//    printf("header len2: %u|\n",tls_h->hl2);
//    printf("header len3: %u|\n",tls_h->hl3);
//    printf("client version: %x|\n",tls_h->c_ver);

    /*
    if(tls_h->rt!=22)//handshake
        return 1;
    if (tls_h->protv!=768 && tls_h->protv!=769 && tls_h->protv!=770 && tls_h->protv!=771)//proto version check
        return 1;
    if(tls_h->ht!=1)//client hello check*/
        return 1;
    return 0;
}
