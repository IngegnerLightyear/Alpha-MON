//
//  lru.c
//  
//
//  Created by Thomas Favale on 05/11/2019.
//

#include "lru.h"

struct lru* newlru(int client_hash, time_t timestamp)
{
    // Allocate memory and assign 'pageNumber'
    struct lru* temp = (struct lru*)malloc(sizeof(lru));
    //struct lru* temp = (struct lru*)rte_malloc(NULL, sizeof(lru), 0);
    temp->client_hash = client_hash;
    temp->timestamp = timestamp;

    // Initialize prev and next as NULL
    temp->prev = temp->next = NULL;

    return temp;
}


void Enqueue(struct names* queue, flow flow_recv, int hash_val, int k_anon, int k_delta)
{
    // Create a new node,
    // And add the new node to the front of queue
    if(DEBUG==1)
    printf("            IN ENQUEUE\n");
    struct lru* tmp = newlru(hash_val, flow_recv.timestamp);
    //tmp->next = queue->head;
    //tmp->prev = NULL;

    if(DEBUG==1)
    printf("            sistemato il puntatore per la testa\n");
    
    // If queue is empty, change both front and rear pointers
    if (queue->n_entry==0)
    {
        if(DEBUG==1)
        printf("        era il primo elemento in lista\n");
        queue->tail = queue->head = tmp;
        //tmp->next = NULL;
        //tmp->prev = NULL;
    }
    else // Else change the front
    {
        tmp->next = queue->head;
        //tmp->prev = NULL;
        queue->head->prev = tmp;
        queue->head = tmp;
    }
    
    //tmp->client_hash = hash_val;
    //tmp->timestamp = timestamp;

    // Add client entry
    queue->client_list[hash_val].active = 1;
    queue->client_list[hash_val].ipv = flow_recv.ipv;
    queue->client_list[hash_val].ipv4_src = flow_recv.ipv4_src;
    queue->client_list[hash_val].ipv4_dst = flow_recv.ipv4_dst;
    queue->client_list[hash_val].ipv6_src = flow_recv.ipv6_src;
    queue->client_list[hash_val].ipv6_dst = flow_recv.ipv6_dst;
    queue->client_list[hash_val].in_port = flow_recv.in_port;
    queue->client_list[hash_val].out_port = flow_recv.out_port;
    queue->client_list[hash_val].protocol = flow_recv.protocol;
    queue->client_list[hash_val].last_seen = flow_recv.timestamp;
    queue->client_list[hash_val].lru_ptr = tmp;

    // increment number of full frames
    queue->n_entry++;
    queue->n_client++;
    //queue->oldest = queue->tail->timestamp;
    
    //Pruning operations
    /*if(queue->n_entry > k_anon)
        prune(queue, timestamp, k_delta);
    queue->oldest = queue->tail->timestamp;*/
}

void prune(struct names *queue, time_t timestamp, int delta)
{
    struct lru *tmp = queue->tail;
    while(tmp->timestamp < timestamp - delta)
    {
        if(DEBUG==1)
        printf("pruning %s", queue->name);
        queue->tail = tmp->prev;
        queue->tail->next = NULL;
        queue->client_list[tmp->client_hash].active = 0;
        queue->client_list[tmp->client_hash].lru_ptr = NULL;
        free(tmp);
        //rte_free(tmp);
        queue->n_entry--;
        tmp = queue->tail;
    }
}

void referencePage(struct names* queue, flow flow_recv, int hash_val, int k_anon, int k_delta)
{
    if(DEBUG==1)
    printf("IN REFERENCEPAGE\n");
    if(DEBUG==1)
    printf("    Client Status: %d\n", queue->client_list[hash_val].active);
    // the page is not in cache, bring it
    if (queue->client_list[hash_val].active == 0)
    {
        if(DEBUG==1)
        printf("        Calling ENQUEUE\n");
        Enqueue(queue, flow_recv, hash_val, k_anon, k_delta);
    }

    // page is there and not at front, change pointer
    else if (queue->client_list[hash_val].lru_ptr != queue->head) {
        if(DEBUG==1)
        printf("        Riordino la lista\n");
        // Unlink rquested page from its current location
        // in queue.
        queue->client_list[hash_val].lru_ptr->prev->next = queue->client_list[hash_val].lru_ptr->next;
        if(DEBUG==1)
        printf("            Link entry precedente con successiva (o NULL) -> OK\n");
        
        if (queue->client_list[hash_val].lru_ptr->next)
            queue->client_list[hash_val].lru_ptr->next->prev = queue->client_list[hash_val].lru_ptr->prev;
        if(DEBUG==1)
        printf("            Link entry successiva con precedente (!= NULL) -> OK\n");
        
        
        // If the requested page is rear, then change rear
        // as this node will be moved to front
        if (queue->client_list[hash_val].lru_ptr == queue->tail) {
            queue->tail = queue->client_list[hash_val].lru_ptr->prev;
            queue->tail->next = NULL;
        }
        if(DEBUG==1)
        printf("            Entry era alla fine -> OK\n");

        // Put the requested page before current front
        queue->client_list[hash_val].lru_ptr->next = queue->head;
        queue->client_list[hash_val].lru_ptr->prev = NULL;
        if(DEBUG==1)
        printf("            Put front 1 -> OK\n");

        // Change prev of current front
        queue->client_list[hash_val].lru_ptr->next->prev = queue->client_list[hash_val].lru_ptr;

        if(DEBUG==1)
        printf("            Put front 2 -> OK\n");
        
        // Change front to the requested page
        queue->head = queue->client_list[hash_val].lru_ptr;
        
        if(DEBUG==1)
        printf("            Put front 3 -> OK\n");
        queue->head->timestamp = flow_recv.timestamp;
    }
    else if (queue->client_list[hash_val].lru_ptr == queue->head)
        queue->head->timestamp = flow_recv.timestamp;
    
    //Pruning operations
    if(queue->n_entry > k_anon)
        prune(queue, flow_recv.timestamp, k_delta);
    queue->oldest = queue->tail->timestamp;
    if(DEBUG==1)
    printf("        Timestamp -> OK\n");
}
