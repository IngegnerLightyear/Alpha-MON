//
//  hash_calculator.h
//  
//
//  Created by Thomas Favale on 05/11/2019.
//

#ifndef hash_calculator_h
#define hash_calculator_h

#include <stdio.h>

#include <stdlib.h>
/*#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>*/
#include "proto_mng.h"

int getHash(__uint128_t, __uint128_t, uint16_t, uint16_t, uint8_t, int);
int nameHash(char *s);
int getHashClient(__uint128_t, int);
uint64_t Uint128Low64(const __uint128_t);
uint64_t Uint128High64(const __uint128_t);
char randChar ();

#endif /* hash_calculator_h */
