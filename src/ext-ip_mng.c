//
//  ext-ip_mng.c
//  a-mon
//
//  Created by Thomas Favale on 13/10/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#include "ext-ip_mng.h"
int external_ip (struct rte_mbuf * packet, struct timespec tp, int ip_origin, struct table_flow * flusso, hash_struct *flowdb, flow newPacket, int k_anon, int k_delta)
{
    int len;
    uint16_t ether_type;
    char buf[MAX_STR];
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in6_addr src_addr_6;
    struct in6_addr dst_addr_6;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr * ipv4_header;
    struct ipv6_hdr * ipv6_header;
    char name[NAME_DNS];
    int flag = 0;
    int ret;
    
    
    eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
    ether_type = htons(eth_hdr->ether_type);

    /* Is IPv4 */
    if (ether_type == 0x0800)
    {
        ipv4_header = rte_pktmbuf_mtod_offset(packet, struct ipv4_hdr *, sizeof(struct ether_hdr) );

        src_addr.s_addr = ipv4_header->src_addr;
        dst_addr.s_addr = ipv4_header->dst_addr;

        if ( VERBOSE > 0)
        {
            printf("ANON:    IPv4\n");
            printf("ANON:    from %s\n", inet_ntoa(src_addr));
            printf("ANON:    to   %s\n", inet_ntoa(dst_addr));
        }

        if (ip_origin==10)//src to anon
        {
            if(flusso->toAnon==-1)
            {
                name[0]= (ipv4_header->src_addr >> 24) & 0xFF;
                name[1]= (ipv4_header->src_addr >> 16) & 0xFF;
                name[2]= (ipv4_header->src_addr >> 8) & 0xFF;
                name[3]= ipv4_header->src_addr & 0xFF;
                name[4]='\0';
                ret = table_add(&flow_db, newPacket, name, k_anon, k_delta);
                //check flows
                if(ret < k_anon)
                {
                    flag++;
                    ipv4_header->src_addr = addressV4_gen();
                    flusso->ipv4_anon = ipv4_header->src_addr;
                }
                if(flusso->toAnon==1)
                {
                    ipv4_header->src_addr = flusso->ipv4_anon;
                }
                
            }
        }
        if (ip_origin==1)//dst to anon
        {
            if(flusso->toAnon==-1)
            {
                name[0]= (ipv4_header->dst_addr >> 24) & 0xFF;
                name[1]= (ipv4_header->dst_addr >> 16) & 0xFF;
                name[2]= (ipv4_header->dst_addr >> 8) & 0xFF;
                name[3]= ipv4_header->dst_addr & 0xFF;
                name[4]='\0';
                ret = table_add(&flow_db, newPacket, name, k_anon, k_delta);
                //check flows
                if(ret < k_anon)
                {
                    flag++;
                    ipv4_header->dst_addr = addressV4_gen();
                    flusso->ipv4_anon = ipv4_header->dst_addr;
                }
            }
            if(flusso->toAnon==1)
            {
                ipv4_header->dst_addr = flusso->ipv4_anon;
            }
        }
        

        if ( VERBOSE > 0)
        {
            printf("ANON:    new from %s\n", inet_ntoa(src_addr));
            printf("ANON:    new to   %s\n", inet_ntoa(dst_addr));
        }
    }
    /* Is IPv6 */
    else if(ether_type == 0x86DD)
    {

        ipv6_header = rte_pktmbuf_mtod_offset(packet, struct ipv6_hdr *, sizeof(struct ether_hdr) );

        rte_memcpy(&src_addr_6.s6_addr, ipv6_header->src_addr, sizeof(src_addr_6.s6_addr));
        rte_memcpy(&dst_addr_6.s6_addr, ipv6_header->dst_addr, sizeof(dst_addr_6.s6_addr));

        if ( VERBOSE > 0){
            printf("ANON:    IPv6\n");
            inet_ntop(AF_INET6, &src_addr_6, buf, MAX_STR);
            printf("ANON:    from %s\n", buf);
            inet_ntop(AF_INET6, &dst_addr_6, buf, MAX_STR);
            printf("ANON:    to   %s\n", buf);
        }

    
        if (ip_origin==10)
        {
            if(flusso->toAnon==-1)
            {
                for(int i=0; i<16; i++)
                {
                    name[i] = ipv6_header->src_addr[i];
                }
                name[16]='\0';
                ret = table_add(&flow_db, newPacket, name, k_anon, k_delta);
                if(ret < k_anon)
                {
                    flag++;
                    addressV6_gen(&src_addr_6.s6_addr);
                    rte_memcpy(ipv6_header->src_addr, &src_addr_6.s6_addr, sizeof(src_addr_6.s6_addr));
                    rte_memcpy(flusso->ipv6_anon, &src_addr_6.s6_addr, sizeof(flusso->ipv6_anon));
                }
            }
            if(flusso->toAnon==1)
            {
                rte_memcpy(ipv6_header->src_addr, &flusso->ipv6_anon, sizeof(flusso->ipv6_anon));
            }
        }
        if (ip_origin==1)
        {
            if(flusso->toAnon==-1)
            {
                for(int i=0; i<16; i++)
                {
                    name[i] = ipv6_header->dst_addr[i];
                }
                name[16]='\0';
                ret = table_add(&flow_db, newPacket, name, k_anon, k_delta);
                if(ret < k_anon)
                {
                    flag++;
                    addressV6_gen(&dst_addr_6.s6_addr);
                    rte_memcpy(ipv6_header->dst_addr, &dst_addr_6.s6_addr, sizeof(dst_addr_6.s6_addr));
                    rte_memcpy(flusso->ipv6_anon, &dst_addr_6.s6_addr, sizeof(flusso->ipv6_anon));
                }
            }
            if(flusso->toAnon==1)
            {
                rte_memcpy(ipv6_header->dst_addr, &flusso->ipv6_anon, sizeof(flusso->ipv6_anon));
            }
        }
        if ( VERBOSE > 0)
        {
            inet_ntop(AF_INET6, &src_addr_6, buf, MAX_STR);
            printf("ANON:    new from %s\n", buf);
            inet_ntop(AF_INET6, &dst_addr_6, buf, MAX_STR);
            printf("ANON:    new to   %s\n", buf);
        }
    }
    return flag;
}

uint32_t addressV4_gen()
{
    uint32_t ul_dst;
    uint32_t random_num = rte_get_tsc_cycles ();
    ul_dst = (random_num & 0xFF) << 24 |
            (random_num >> 16 & 0xFF) << 16 |
            (random_num >> 8 & 0xFF) << 8 |
            (127 & 0xFF);
    return ul_dst;
}

void addressV6_gen(struct in6_addr * tmp)
{
    uint8_t random_num;
    tmp->s6_addr[0] = 254;
    tmp->s6_addr[1] = 128;
    for(int i=2; i<16;i++)
    {
        random_num = rte_get_tsc_cycles ();
        tmp->s6_addr[i] = random_num;
    }
}
//check random ip
/*int main(void)
{
  uint32_t ul_dst;
  srand(time(NULL));
  uint32_t random_num = rand();
  const uint8_t net = 127;

  unsigned char bytes[4];
  //bytes[0] = random_num & 0xFF;
  //bytes[1] = (random_num >> 8) & 0xFF;
  //bytes[2] = (random_num >> 16) & 0xFF;
  //bytes[3] = (net) & 0xFF;
  //printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);


  
  ul_dst = (127 & 0xFF) << 24 |
          (random_num >> 16 & 0xFF) << 16 |
          (random_num >> 8 & 0xFF) << 8 |
          (random_num & 0xFF);

  printf("%u\n",ul_dst);

  bytes[0] = ul_dst & 0xFF;
  bytes[1] = (ul_dst >> 8) & 0xFF;
  bytes[2] = (ul_dst >> 16) & 0xFF;
  bytes[3] = (ul_dst >> 24) & 0xFF;
  printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);

  return 0;
}*/
