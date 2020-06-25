//
//  dns_mng.c
//  
//
//  Created by Thomas Favale on 08/11/2019.
//

#include "dns_mng.h"


dns_header * dns_header_extractor (struct rte_mbuf * packet, int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    //dns_header *dns;
    size_t len;
    if(ipv4_header!=NULL)
    {
        if(protocol == 0)
        {
            len = offset_extractor (protocol, ipv4_header, ipv6_header);
            if(len>=packet->pkt_len)
                return NULL;
            else
                return rte_pktmbuf_mtod_offset(packet, dns_header*, len );
        }
        else if(protocol == 1)
        {
            len = offset_extractor (protocol, ipv4_header, ipv6_header);
            if(len>=packet->pkt_len)
                return NULL;
            else
                return rte_pktmbuf_mtod_offset(packet, dns_header*, len );
            //return rte_pktmbuf_mtod_offset( packet, dns_header*, offset_extractor (protocol, ipv4_header, ipv6_header)  );
            /*printf("flag: %d, %d", (int)dns->qr, (int)htons(dns->qr));
            printf("\n %d ID.",ntohs(dns->id));
            printf("\n %d Questions.",ntohs(dns->q_count));
            printf("\n %d Answers.",ntohs(dns->ans_count));
            printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
            printf("\n %d Additional records.\n\n",ntohs(dns->add_count));*/
        }
    }
    else
    {
        if(protocol == 0)
            return rte_pktmbuf_mtod_offset(packet, dns_header*, offset_extractor (protocol, ipv4_header, ipv6_header) );
        else if(protocol == 1)
            return rte_pktmbuf_mtod_offset(packet, dns_header*, offset_extractor (protocol, ipv4_header, ipv6_header) );
    }
    //return dns;
}

size_t offset_extractor (int protocol, struct ipv4_hdr * ipv4_header, struct ipv6_hdr * ipv6_header)
{
    if(ipv4_header!=NULL)
    {
        if(protocol == 0)
            return  sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+sizeof(struct tcp_hdr);
        else if(protocol == 1)
            return sizeof(struct ipv4_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
    else
    {
        if(protocol == 0)
            return  sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+sizeof(struct tcp_hdr);
        else if(protocol == 1)
            return sizeof(struct ipv6_hdr)+sizeof(struct ether_hdr)+sizeof(struct udp_hdr);
    }
}

/*ret_info dns_parse_question(char *buff)
{
    int len=0;
    char str;
    printf("parsing\n");
    while(len==43)
    {
        str=++*buff;
        printf("%c", str);
        len++;
    }
}*/

/* u_char* */ /*void*/ int ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name = NULL;
    unsigned int p=0,jumped=0,offset;
    int i , j;
    int cnt, first,ctrl;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
    if(name==NULL)
        return 1;
 
    name[0]='\0';
    first=0;
    ctrl=0;
    
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            if(first==0 && ctrl==0)
            {
                cnt=(int)*reader;
                ctrl++;
            }
            else if(first==cnt)
            {
                first=0;
                cnt=(int)*reader;
            }
            else
            {
                *reader = randChar();
                //name[p++]=*reader;
                first++;
            }
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    /*for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    printf("name: %s\n", name);
    return name;*/
    return 0;
}
