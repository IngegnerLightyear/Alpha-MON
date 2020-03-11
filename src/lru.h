//
//  lru.h
//  
//
//  Created by Thomas Favale on 05/11/2019.
//

#ifndef lru_h
#define lru_h

#include <stdio.h>
#include <stdlib.h>
#include <rte_malloc.h>
#include "proto_mng.h"

// A utility function to create a new Queue Node. The queue Node
// NOT TO BE CALLED
struct lru* newlru(int, time_t);

// A function to add a frame with given info
// NOT TO BE CALLED
void Enqueue(struct names*, flow , int, int, int);

// A utility function to delete frames outside the window
void prune(struct names *,time_t, int);

// This function is called to do a lookup
// from cache (or memory). There are two cases:
// 1. Frame is not there in memory, we bring it in memory and add to the front
// of queue
// 2. Frame is there in memory, we move the frame to front of queue
// NOT TO BE CALLED
void referencePage(struct names*, flow, int, int, int);

#endif /* lru_h */
