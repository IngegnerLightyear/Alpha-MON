//
//  hash_calculator.c
//  
//
//  Created by Thomas Favale on 05/11/2019.
//

#include "hash_calculator.h"
uint64_t Uint128Low64(const __uint128_t x) { return (uint64_t)x; }
uint64_t Uint128High64(const __uint128_t x) { return (x >> 64); }

int getHash(__uint128_t sip, __uint128_t dip, uint16_t sp, uint16_t dp, uint8_t ptl, int max_dim)
{
    return (sip ^ dip ^ sp ^ dp ^ ptl)%max_dim;
    /*int dsp = dip ^ sip;
    int dsp_h16 = (dsp & 0xffff0000) >> 16;
    int dsp_l16 = dsp & 0x0000ffff;
    int dspt_h16_s = dsp_h16 ^ sp;
    int dspt_l16_d = dspt_h16_s ^ dp;
    int dsp16 = (dspt_l16_d ^ dsp_l16) ^ ptl;
    int dsp_h = ( dsp16 & 0x0f00) >> 8;
    int dsp_m = ( dsp16 & 0x00f0) >> 4;
    int dsp4 = dsp_h ^ dsp_m;
    int dsp12 = dsp_h | (dsp4 << 8);
    return  (dsp12 >> 4)%max_dim;*/
    //old
    /*printf("%d ... %d ... %d ... %d ... %d\n", abs(sip),abs(dip),abs(sp),abs(dp),abs(ptl));
    return (int)abs((sip*dip*sp*dp*ptl)%1000);*/
}

int nameHash(char *s) {
    /*int p = 31;
    int hash_value = 0;
    int p_pow = 1;
    for (int i=0; i<strlen(s); i++) {
    //int i = 0;
    //while (s[i]!=0){
        hash_value = (hash_value + (s[i] - 'a' + 1) * p_pow) % FLOW_TABLE_SIZE;
        p_pow = (p_pow * p) % FLOW_TABLE_SIZE;
    //    i++;
    }
    return hash_value;*/
    unsigned int hash = 5381;
    int c;

    while (c = *s++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash % FLOW_TABLE_SIZE;
}

int getHashClient(__uint128_t sip, int max_dim)
{
    // Murmur-inspired hashing.
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;
    uint64_t a = (Uint128Low64(sip) ^ Uint128High64(sip)) * kMul;
    a ^= (a >> 47);
    uint64_t b = (Uint128High64(sip) ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b%max_dim;
}

char randChar ()
{
    //return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[random () % 26];
    //return 'a';
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[rte_get_tsc_cycles () % 26];
}
