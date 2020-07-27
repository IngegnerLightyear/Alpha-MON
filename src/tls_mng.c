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
    size_t len;
    struct tcp_hdr *tcp_header;
    tcp_header = rte_pktmbuf_mtod_offset(packet, struct tcp_hdr *, sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr) );
    
    len = offset_extractor_tls (protocol, ipv4_header, ipv6_header, tcp_header->data_off);
    if (len == 0)
        return NULL;
    else
        return rte_pktmbuf_mtod_offset(packet, tls_header_v2*, len );
}

size_t offset_extractor_tls (int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint8_t offset)
{
    offset=(offset>>4)*4;//offset counts options too
    if (offset>60)
        return 0;
    if(ipv4_header!=NULL)
    {
        if(protocol == 0)
            return sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+offset;
        else if(protocol == 1)
            return sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
    else
    {
        if(protocol == 0)
            return sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+offset;
        else if(protocol == 1)
            return sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
}



int tlsHelloEntry (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint8_t offset, flow newPacket, hash_struct *flow_db, int k_anon, int k_delta, crypto_ip *self, int id, int core)
{
    /*char *buff = NULL;
    char *buffstart = NULL, *buffpay=NULL;
    unsigned char len;
    
    buff = rte_pktmbuf_mtod_offset(packet, char *, offset_extractor_tls(protocol, ipv4_header, ipv6_header, offset));
    buffstart = buff;//point to tls start
    buff += (9*sizeof(unsigned char)+sizeof(unsigned short)+4);
    len = buff;
    buff += atoi(len)+sizeof(unsigned char);//session id*/
    
//char *get_TLS_SNI(unsigned char *bytes, int* len)
//{
    //cast operations
    //int len = 0;//optional
    unsigned char *bytes = NULL;
    bytes = rte_pktmbuf_mtod_offset(packet, char *, offset_extractor_tls(protocol, ipv4_header, ipv6_header, offset));
    int ret = 0;
    int flag = 0;
    unsigned char *curr;
    unsigned char sidlen = bytes[43];
    curr = bytes + 1 + 43 + sidlen;
    unsigned short cslen = ntohs(*(unsigned short*)curr);
    curr += 2 + cslen;
    unsigned char cmplen = *curr;
    curr += 1 + cmplen;
    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
    curr += 2;
    unsigned short ext_type = 1;
    unsigned short ext_len;
    while(curr < maxchar && ext_type != 0)
    {
        ext_type = ntohs(*(unsigned short*)curr);
        curr += 2;
        ext_len = ntohs(*(unsigned short*)curr);
        curr += 2;
        if(ext_type == 0)
        {
            curr += 3;
            unsigned short namelen = ntohs(*(unsigned short*)curr);
            curr += 2;
            //*len = namelen;//optional
            if(DEBUG==1)
                printf("--- %s || %d || (%d)---\n", curr, namelen, strlen(curr));
            if(namelen == 0 || namelen!=strlen(curr))
                return;
            ret = table_add(flow_db, newPacket, curr, k_anon, k_delta);
            if(DEBUG==1)
                printf("Returned: %d\n", ret);
            if(ret < k_anon)
            {
                flag++;
                if(DEBUG==1)
                    printf("Removing: %s --> len: %d\n", curr, namelen);
                for (int j = 0; j < namelen; j++)
                {
                    if(*curr != '.')
                        *curr++=randChar ();
                    else
                        *curr++;
                }
            }
            return flag;
            //return (char*)curr;
        }
        else curr += ext_len;
    }
    if (curr != maxchar)
    {
        if(DEBUG==1)
            printf("incomplete SSL Client Hello\n");
        return flag; //SNI was not present
    }
//}
    
}
