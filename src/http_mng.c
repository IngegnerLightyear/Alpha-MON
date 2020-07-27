//
//  http_mng.c
//  a-mon
//
//  Created by Thomas Favale on 06/07/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#include "http_mng.h"

char * http_header_extractor (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    size_t len;
    struct tcp_hdr *tcp_header;
    tcp_header = rte_pktmbuf_mtod_offset(packet, struct tcp_hdr *, sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr) );
    
    len = offset_extractor_http (protocol, ipv4_header, ipv6_header, tcp_header->data_off);
    if (len == 0)
        return NULL;
    else
        return rte_pktmbuf_mtod_offset(packet, char *, len );
}

size_t offset_extractor_http (int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint8_t offset)
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

int httpEntry (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header, uint8_t offset, flow newPacket, hash_struct *flow_db, int k_anon, int k_delta, crypto_ip *self, int id, int core)
{
    int flag = 0;
    int i = 0;
    int ret;
    char *ptr=NULL, *ptr_start=NULL, *ptr_next_field=NULL, *ptr2=NULL;
    char *pkt=NULL;
    char name[NAME_DNS];
    char c;
    int len=0, len_start;
    
    name[0]='\0';
    
    if(DEBUG==1)
        printf("In httpEntry\n", ret);
    pkt = http_header_extractor(packet, protocol, ipv4_header, ipv6_header);
    len  = offset_extractor_http(protocol, ipv4_header, ipv6_header, offset);
    //len = ptr - pkt;
    if(pkt==NULL)
        return flag;
    if(len==0)
        return flag;
    //to go back in the future
    len_start = len;
    //ptr_start = pkt;
    
    if(DEBUG==1)
        printf("Header Extracted\n");

    
    //delete Host name
    //ptr = ptr_start;
    ptr = strcasestr(pkt, "HOST");
//    ptr_next_field = strcasestr(pkt, "USER-AGENT");
    if(ptr == NULL)// || ptr_next_field == NULL)
        return flag;
    len = len + (ptr - pkt) + 6;
    //len+=6;
    if(len>=packet->pkt_len)
        return flag;
    ptr+=6;//overcome "HOST: "
    if(DEBUG==1)
        printf("Overcome HOST: \n");
    ptr_start = ptr;
    if(DEBUG==1)
        printf("Pointer move\n");
    
    len++;
    while(*ptr!='\r' && *ptr+1!='\n')
    {
        if(len>=packet->pkt_len)
        {
            if(DEBUG==1)
                printf("Malformed: Truncated\n");
            return flag;
        }
//        if(ptr_next_field - ptr <= 0)
//            return flag;
  
        if(i>63)
        {
            if(DEBUG==1)
                printf("Malformed: Too long\n");
            return flag;
        }
        
        if(DEBUG==1)
            printf("%c", *ptr);
        c = *ptr++;
        name[i] = c;
        i++;
        len++;
    }
    if(DEBUG==1)
        printf("\n");
    if(len>=packet->pkt_len)
        return flag;
    name[i] = '\0';
    if(strlen(name)==0)
        return;
    if(DEBUG==1)
        printf("%s\n", name);
    
    ret = table_add(flow_db, newPacket, name, k_anon, k_delta);
    if(DEBUG==1)
        printf("Returned: %d\n", ret);
    //removing name
    if(ret < k_anon)
    {
        flag++;
        if(DEBUG==1)
            printf("Removing: %s\n", name);
        ptr=ptr_start;
        for(i=0; i<strlen(name); i++)
        {
            if(*ptr != '.')
                *ptr++=randChar();
            else
                *ptr++;
        }
    
        //delete URI
        len = len_start;
        ptr = strcasestr(pkt, "GET");
        ptr2 = strcasestr(pkt, "POST");
        if(ptr != NULL)
        {
            len+=4;
            if(len>=packet->pkt_len)
                return flag;
            ptr+=4;
        }
        else if (ptr2 != NULL)
        {
            len+=5;
            if(len>=packet->pkt_len)
                return flag;
            ptr = ptr2;
            ptr+=5;
        }
        else
            return flag;
        
        ptr_next_field = strcasestr(pkt, "HTTP");
        if(ptr_next_field==NULL)
            return flag;
        
        while(*ptr!=' ')
        {
            len++;
            if(len>=packet->pkt_len)
                return flag;
            if(ptr_next_field - ptr <= 0)
                return flag;
            if(*ptr != '.' && *ptr != '/')
                *ptr++=randChar();
            else
                *ptr++;
        }
    
        //delete Refer <-problema qui!!!
        len = len_start;
        ptr = strcasestr(pkt, "REFER");
        if(ptr != NULL)
        {
            len+=16;
            if(len>=packet->pkt_len)
                return flag;
            ptr+=16;
        }
        else
            return flag;
        i=0;
        while(*ptr!='\r' && *ptr+1!='\n')
        {
            len++;
            if(len>=packet->pkt_len)
                return flag;
            if(*ptr != '.' && *ptr != '/')
                *ptr++=randChar();
            else
                *ptr++;
            if(i>63)
            {
                if(DEBUG==1)
                    printf("Malformed: Too long\n");
                return flag;
            }
            i++;
        }
    }
    return flag;
}
