#ifndef CRYPTO_H
#define CRYPTO_H
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include "rijndael.h"
#include "traffic_anon.h"
#include "rijndael.h"

#define MAX_CRYPTIO_CACHE_SIZE 130000
#define CRYPTO_IPV6_MASK_0 0xffffffff
#define CRYPTO_IPV6_MASK_1 0xf0f0f0f0
#define CRYPTO_IPV6_MASK_2 0x0f0f0f0f
#define CRYPTO_IPV6_MASK_3 0x00000000

#define CPKEY_RANDOM 1
#define CPKEY_FILE   2
#define CPKEY_FILE64 3
#define CPKEY_CLI    4

#endif

/* Redefine the initial hash size to a large value, to avoid/reduce the automatic rehashing */

#define HASH_INITIAL_NUM_BUCKETS 131072      /* initial number of buckets        */
#define HASH_INITIAL_NUM_BUCKETS_LOG2 17     /* lg2 of initial number of buckets */

/* Use the Bernstein hash function */
#define HASH_FUNCTION HASH_BER

#include "uthash.h" /* Include the generic hash table */

#define KEY_SIZE 32

#define CACHEBITS 20
#define CACHESIZE (1 << CACHEBITS)

typedef struct key_hashT {
  in_addr_t key;
  in_addr_t cpan_addr;
  UT_hash_handle hh;
}key_hashT;

#ifdef SUPPORT_IPV6
typedef struct key6_hashT {
  struct in6_addr key;
  struct in6_addr cpan_addr;
  UT_hash_handle hh;
}key6_hashT;
#endif

typedef struct crypto_ip
{
        key_hashT *address_hash;
        #ifdef SUPPORT_IPV6
        key6_hashT *address6_hash;
        #endif
        int crypto_total_hit;
	int crypto_total_insert;
	int crypto_total_miss;
        #ifdef SUPPORT_IPV6
        int crypto_total_hit_ipv6;
	int crypto_total_insert_ipv6;
	int crypto_total_miss_ipv6;
        #endif
        uint8_t m_key[MAX_INTERFACES][16];
        uint8_t m_pad[16];
        uint32_t *enc_cache;
        uint32_t fullcache[2][2];
}crypto_ip;

/* Reentrant data structure [core][interface] */
rijndael rijndael_OP[100][MAX_INTERFACES];

void initialize_crypto(crypto_ip *, char *value, int, int );
void      encrypt_init(crypto_ip *, char *, int, int, int );
uint32_t  encrypt_ip(crypto_ip *, uint32_t, int, int );
void      store_crypto_ip(crypto_ip *, struct in_addr *, int, int);
in_addr_t retrieve_crypto_ip(crypto_ip *, struct in_addr *, int, int );
char      *StringEncryptedBase64(char *, int, int);

#ifdef SUPPORT_IPV6
void      encrypt_ipv6(crypto_ip *, struct in6_addr *,struct in6_addr *, int, int);
void      store_crypto_ipv6(crypto_ip *, struct in6_addr *, int, int);
struct in6_addr *retrieve_crypto_ipv6(crypto_ip *, struct in6_addr *, int, int );
#endif

uint32_t anonymize( crypto_ip *, const uint32_t orig_addr, int, int );
uint32_t pp_anonymize( crypto_ip *, const uint32_t orig_addr, int, int );
uint32_t cpp_anonymize( crypto_ip *, const uint32_t orig_addr, int, int );
void panon_init_decrypt(crypto_ip *, const uint8_t * key, int, int );
void panon_init(crypto_ip *, const char * key, int, int);
void panon_init_cache(crypto_ip *);
