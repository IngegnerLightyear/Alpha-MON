//
//  flow_mng.c
//  a-mon
//
//  Created by Thomas Favale on 26/06/2020.
//  Copyright © 2020 Thomas Favale. All rights reserved.
//

#include "flow_mng.h"

void flow_table_init()
{
    flow_struct.table = malloc(TCP_UDP_FLOWS*sizeof(struct table_flow));
    if(flow_struct.table == NULL)
        return;
    flow_struct.bitMap  = malloc(TCP_UDP_FLOWS*sizeof(struct entry_access));
    if(flow_struct.bitMap == NULL)
        return;
    for(int i=0; i<TCP_UDP_FLOWS; i++)
    {
        flow_struct.table[i].toAnon = -1;
        flow_struct.table[i].prev = NULL;
        flow_struct.table[i].next = NULL;
        flow_struct.bitMap[i].number = 0;
        if (pthread_mutex_init(&flow_struct.bitMap[i].permission, NULL) != 0)
        {
            printf("\n mutex init failed\n");
            return;
        }
    }
}

struct table_flow * reference_flow(flow * data)
{
    int hash;
    struct table_flow *curr, *last;
    int found = 0;
    int first_free = 0;
    float probability;
    int seed;
    
    if(data->ipv==4)
        hash = getHash(data->ipv4_src, data->ipv4_dst, data->in_port, data->out_port, data->protocol, TCP_UDP_FLOWS);
    else
        hash = getHash(data->ipv6_src, data->ipv6_dst, data->in_port, data->out_port, data->protocol, TCP_UDP_FLOWS);
    
    pthread_mutex_lock(&flow_struct.bitMap[hash].permission);
    
    curr = &flow_struct.table[hash];
    
    //find flow
    while(curr!=NULL)
    {
         //match?
        if(curr->ipv4_src==data->ipv4_src && curr->ipv4_dst==data->ipv4_dst
           || curr->ipv4_src==data->ipv4_dst && curr->ipv4_dst==data->ipv4_src)
                if(curr->in_port==data->in_port && curr->out_port==data->out_port
                   ||curr->out_port==data->in_port && curr->in_port==data->out_port)
                    if(curr->protocol == data->protocol)
                    {
                        found = 1;
                        curr->timestamp = data->timestamp;
                        break;
                    }
        //garbage collection
        seed = (int)rte_get_tsc_cycles ();
        seed =  (214013*seed+2531011);
        probability = ((seed>>16)&0x7FFF)%100;
        if(probability>50)
        {
            if(data->timestamp - curr->timestamp > T_OUT)
            {
                if(curr->prev!=NULL)
                {
                    struct table_flow *tmp = curr;
                    curr = curr->next;
                    if(tmp->prev->prev!=NULL)
                    {
                        curr->prev->prev->next = curr;
                        curr->prev = curr->prev->prev;
                    }
                    else
                    {
                        tmp->prev->next = curr;
                        curr->prev = tmp->prev;
                    }
                    free(tmp);
                }
                else
                    first_free = 1;
            }
        }
        if(curr->next==NULL)
            last = curr;
        curr= curr->next;
    }
    //adding
    if(found == 0)
    {
        if(first_free==1)
        {
            flow_struct.table[hash].ipv = data->ipv;
            flow_struct.table[hash].ipv4_src = data->ipv4_src;
            flow_struct.table[hash].ipv4_dst = data->ipv4_dst;
            flow_struct.table[hash].ipv6_src = data->ipv6_src;
            flow_struct.table[hash].ipv4_dst = data->ipv4_dst;
            flow_struct.table[hash].in_port = data->in_port;
            flow_struct.table[hash].out_port = data->out_port;
            flow_struct.table[hash].protocol = data->protocol;
            flow_struct.table[hash].timestamp = data->timestamp;
            flow_struct.table[hash].toAnon = -1;
            curr = &flow_struct.table[hash];
        }
        else
        {
            struct table_flow *new;
            new=malloc(sizeof(struct table_flow));
            last->next = new;
            new->prev = last;
            new->next = NULL;
            new->ipv = data->ipv;
            new->ipv4_src = data->ipv4_src;
            new->ipv4_dst = data->ipv4_dst;
            new->ipv6_src = data->ipv6_src;
            new->ipv4_dst = data->ipv4_dst;
            new->in_port = data->in_port;
            new->out_port = data->out_port;
            new->protocol = data->protocol;
            new->timestamp = data->timestamp;
            new->toAnon = -1;
            curr = new;
        }
    }
    pthread_mutex_unlock(&flow_struct.bitMap[hash].permission);
    return curr;
}


