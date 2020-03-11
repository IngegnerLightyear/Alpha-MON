#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include "crypto_ip.h"
#include "base64.h"

//#include "rijndael.h"

/* Redefine the initial hash size to a large value, to avoid/reduce the automatic rehashing */

//#define HASH_INITIAL_NUM_BUCKETS 131072      /* initial number of buckets        */
//#define HASH_INITIAL_NUM_BUCKETS_LOG2 17     /* lg2 of initial number of buckets */

/* Use the Bernstein hash function */
//#define HASH_FUNCTION HASH_BER

//#include "uthash.h" /* Include the generic hash table */

/*#define KEY_SIZE 32

struct key_hashT {
  in_addr_t key;
  in_addr_t cpan_addr;
  UT_hash_handle hh;
};

#ifdef SUPPORT_IPV6
struct key6_hashT {
  struct in6_addr key;
  struct in6_addr cpan_addr;
  UT_hash_handle hh;
};
#endif*/

//struct key_hashT *address_hash = NULL;
//#ifdef SUPPORT_IPV6
//struct key6_hashT *address6_hash = NULL;
//#endif

void add_address(crypto_ip * self, in_addr_t src, in_addr_t cpan_addr) {
    key_hashT *s,*tmp_entry;

    s = (key_hashT *)malloc(sizeof(key_hashT));
    s->key = src;
    s->cpan_addr = cpan_addr;
    HASH_ADD_INT( self->address_hash, key, s );  /* id: name of key field */
    
    /* Manage the hash as a LRU cache */
    if (HASH_COUNT(self->address_hash) > MAX_CRYPTIO_CACHE_SIZE)
      {
        HASH_ITER(hh, self->address_hash, s, tmp_entry)
         {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
           HASH_DELETE(hh, self->address_hash, s);
           free(s);
           break;
	 }
      }
}

#ifdef SUPPORT_IPV6
void add_address6(crypto_ip * self,struct in6_addr *src, struct in6_addr *cpan_addr) {
    key6_hashT *s,*tmp_entry;

    s = (key6_hashT *)malloc(sizeof(key6_hashT));
    rte_memcpy(&(s->key),src,sizeof(struct in6_addr));
    rte_memcpy(&(s->cpan_addr),cpan_addr,sizeof(struct in6_addr));
    HASH_ADD( hh, self->address6_hash, key, sizeof(s->key), s );  /* id: name of key field */
    
    /* Manage the hash as a LRU cache */
    if (HASH_COUNT(self->address6_hash) > MAX_CRYPTIO_CACHE_SIZE)
      {
        HASH_ITER(hh, self->address6_hash, s, tmp_entry)
         {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
           HASH_DELETE(hh, self->address6_hash, s);
           free(s);
           break;
	 }
      }
}
#endif

key_hashT *find_address(crypto_ip * self,in_addr_t src) {
    key_hashT *s;

    HASH_FIND_INT( self->address_hash, &src, s );  /* s: output pointer */
    
    /* Manage the hash as a LRU cache */
    if (s) {
      // remove it (so the subsequent add will throw it on the front of the list)
      HASH_DELETE(hh, self->address_hash, s);
      HASH_ADD(hh, self->address_hash, key, sizeof(s->key), s);
      return s;
     }
    return s;
}

#ifdef SUPPORT_IPV6
key6_hashT *find_address6(crypto_ip * self,struct in6_addr *src) {
    key6_hashT *s;

    HASH_FIND( hh, self->address6_hash, src, sizeof(s->key), s );  /* s: output pointer */
    
    /* Manage the hash as a LRU cache */
    if (s) {
      // remove it (so the subsequent add will throw it on the front of the list)
      HASH_DELETE(hh, self->address6_hash, s);
      HASH_ADD(hh, self->address6_hash, key, sizeof(s->key), s);
      return s;
     }
    return s;
}
#endif

//int crypto_total_hit,crypto_total_insert,crypto_total_miss;
//#ifdef SUPPORT_IPV6
//int crypto_total_hit_ipv6,crypto_total_insert_ipv6,crypto_total_miss_ipv6;
//#endif

void initialize_crypto(crypto_ip * self,char *value, int id, int core)
{
    char *key;
    char *keyfile;
    char *enc_key;
    char date[50];
    char line[121];
    char *decoded_key = NULL;
    int flen,i;
    in_addr_t ip1,ip2;
    #ifdef SUPPORT_IPV6
    struct in6_addr ip6_1,ip6_2;
    #endif

    init_rijndael_OP(&rijndael_OP[core][id]);

    self->address_hash = NULL;
    #ifdef SUPPORT_IPV6
    self->address6_hash = NULL;
    #endif
    self->enc_cache = 0;

    key = (char *) malloc(sizeof(char) * KEY_SIZE);
    memset(key,0,KEY_SIZE*sizeof(char));

    if (value==NULL){
        printf("ANON: Invalid key\n");
        exit(1);
    }
       
    printf("ANON: Setting IP encryption key to: %s\nANON: Interface %d, Core %d\n", value, id, core);

    decoded_key=(char *)unbase64(value,strlen(value),&flen);

    if (flen>KEY_SIZE){
        printf("ANON: Key is too long (%d): using only the first %d bytes\n",flen, KEY_SIZE);
        rte_memcpy(key,decoded_key,KEY_SIZE*sizeof(char));
    }
    else
    {
        rte_memcpy(key,decoded_key,flen*sizeof(char));
    }
	if (flen<KEY_SIZE)
    {
        printf("ANON: Key shorter than %d bytes: padding with zeros\n",KEY_SIZE);
    }

    encrypt_init(self, key,KEY_SIZE, id, core);

    /* There is a "bug" due to encrypt_ip internal cache initialization, 
     so "0.0.0.0" is actually not encrypted if it is the argument of 
     either the first or the second function call.
     Call the function twice with other arguments.
    */
    encrypt_ip(self, 1, id, core);
    encrypt_ip(self, 2, id, core);

    /* Insert one address (0.0.0.0) just to inizialize the hash to the full size */
    ip1 = inet_addr("0.0.0.0");
    ip2 = htonl(encrypt_ip(self, htonl(ip1), id, core));
    add_address(self, ip1, ip2);

    self->crypto_total_hit = 0;
    self->crypto_total_insert = 1;
    self->crypto_total_miss = 0;

    #ifdef SUPPORT_IPV6
    /* Insert one address (::) just to inizialize the hash to the full size */
    inet_pton(AF_INET6,"::",&ip6_1);
    encrypt_ipv6(self, &ip6_2,&ip6_1, id, core);
    add_address6(self, &ip6_1,&ip6_2);

    self->crypto_total_hit_ipv6    = 0;
    self->crypto_total_insert_ipv6 = 1;
    self->crypto_total_miss_ipv6   = 0;
    #endif
  
    if (enc_key!=NULL) free(enc_key);
    if (decoded_key!=NULL) free(decoded_key);
    return;

}

void encrypt_init(crypto_ip * self, char *key, int keysize, int id, int core)
{
  char cryptopan_key[32];
  memset(cryptopan_key,0,sizeof(cryptopan_key));

  rte_memcpy(cryptopan_key,key,keysize<sizeof(cryptopan_key)?keysize:sizeof(cryptopan_key));
  panon_init(self, cryptopan_key, id, core);
}

uint32_t encrypt_ip(crypto_ip * self, uint32_t orig_addr, int id, int core) 
{
  return cpp_anonymize(self, orig_addr, id, core);
}

void store_crypto_ip(crypto_ip * self, struct in_addr *address, int id, int core)
{
  in_addr_t ip_entry;
  struct key_hashT *entry;
  
  entry = find_address(self, address->s_addr);

  if (entry == NULL)
   {
     ip_entry = htonl(encrypt_ip(self, htonl(address->s_addr), id, core));
     add_address(self, address->s_addr,ip_entry);
     self->crypto_total_insert++;
   }
  else
  {
    self->crypto_total_hit++;
  }

}

in_addr_t retrieve_crypto_ip(crypto_ip * self, struct in_addr *address, int id, int core)
{
  in_addr_t ip_entry;
  struct key_hashT *entry;
  
  entry = find_address(self, address->s_addr);

  if (entry==NULL)
   {
     ip_entry = htonl(encrypt_ip(self, htonl(address->s_addr), id, core));
     add_address(self, address->s_addr,ip_entry);
     self->crypto_total_insert++;
     self->crypto_total_miss++;

     return ip_entry;
   }
  else
  {
    return entry->cpan_addr;
  }
}

#ifdef SUPPORT_IPV6
void encrypt_ipv6(crypto_ip * self, struct in6_addr *enc_addr,struct in6_addr *orig_addr, int id, int core)
{
  /*
   This is a horrendous hack, but the simplest way to encrypt our IPv6 address is to apply
   the cryptopan encryption on the 4 dwords making the IP address.
   Since the same dword would be encrypted to the same pattern beside the position, 
   addresses like ::1 or with a lot of adjacent :0:0: would be immediately identified.
   For this reason we actually XOR a different bit-pattern to each dword. 
   This should in any case maintain the prefix-preservation property.
  */
  enc_addr->s6_addr32[0] = htonl(encrypt_ip(self, htonl(orig_addr->s6_addr32[0] ^ CRYPTO_IPV6_MASK_0 ), id, core));
  enc_addr->s6_addr32[1] = htonl(encrypt_ip(self, htonl(orig_addr->s6_addr32[1] ^ CRYPTO_IPV6_MASK_1 ), id, core));
  enc_addr->s6_addr32[2] = htonl(encrypt_ip(self, htonl(orig_addr->s6_addr32[2] ^ CRYPTO_IPV6_MASK_2 ), id, core));
  enc_addr->s6_addr32[3] = htonl(encrypt_ip(self, htonl(orig_addr->s6_addr32[3] ^ CRYPTO_IPV6_MASK_3 ), id, core));
}

void store_crypto_ipv6(crypto_ip * self, struct in6_addr *address, int id, int core)
{
  struct in6_addr ip6_entry;
  struct key6_hashT *entry;
  
  entry = find_address6(self, address);

  if (entry == NULL)
   {
     encrypt_ipv6(self, &ip6_entry,address, id, core);
     add_address6(self, address,&ip6_entry);
     self->crypto_total_insert_ipv6++;
   }
  else
  {
    self->crypto_total_hit_ipv6++;
  }

}

struct in6_addr *retrieve_crypto_ipv6(crypto_ip * self, struct in6_addr *address, int id, int core)
{
  static struct in6_addr ip6_entry;
  struct key6_hashT *entry;
  
  entry = find_address6(self, address);

  if (entry==NULL)
   {
     encrypt_ipv6(self, &ip6_entry,address, id, core);
     add_address6(self, address,&ip6_entry);
     self->crypto_total_insert_ipv6++;
     self->crypto_total_miss_ipv6++;

     return &ip6_entry;
   }
  else
  {
    return &(entry->cpan_addr);
  }
}

#endif
char *StringEncryptedBase64(char *string, int id, int core)
{
  /* 
   * Encrypts the argument string using the Rijndael cypher (ECB) and the key already defined 
   * for CryptoPAn. Not particularly strong, but it's the solution requiring the minimum effort,
   * since all the code is already there. Actually, only the first 128 bits of the CryptoPAn key
   * are used, since CryptoPAn uses the other 128 bits to initialize the internal pad used 
   * by the algorithm. This means that you must use only half of the key for decryption. 
   */
  int enc_string_set = 1;

  /*
   * Instead of using fixed sized static buffers, we pre-allocate one of reasonable size, then
   * we increase it if needed. The buffer increase should not happen more than once or twice
   * during the program lifetime.
   */
#define SE_BUFFER_SIZE       80  /* Possibly >16 bytes that is the minimum encryption block size */
#define SE_BUFFER_SIZE_B64  120  /* At least SE_BUFFER_SIZE * 4/3, so we keep it to 1.5 times    */
  
  static char *in_buffer = NULL;       /* Buffer pointers */
  static char *enc_out_buffer = NULL;
  static char *b64_result = NULL;
  static int  in_buffer_size = 0;      /* Current buffer sizes */
  static int  enc_out_buffer_size = 0;
  static int  b64_result_size = 0;
 
  int input_len, padded_len, retval,flen;
  char *b64_enc_string;

  if (in_buffer==NULL) {
    // Initializazion
    in_buffer = (char *)malloc(SE_BUFFER_SIZE*sizeof(char));
    in_buffer_size = SE_BUFFER_SIZE;
    
    enc_out_buffer = (char *)malloc(SE_BUFFER_SIZE*sizeof(char));
    enc_out_buffer_size = SE_BUFFER_SIZE;
    
    b64_result = (char *)malloc(SE_BUFFER_SIZE_B64*sizeof(char));
    b64_result_size = SE_BUFFER_SIZE_B64;
  }
  
  if (enc_string_set==1) {
    /* Only do the work if the encrytion environment has been initialized (-Y) */

    input_len = strlen(string);
    
      // Since we work with blocks of 16 bytes, the buffer must contain the string
      // even if padded to the next multiple of 16 bytes.
    if ( (input_len + 15) > in_buffer_size ) {
      // Reallocate the static buffers: it should't happen too often.
      int times = 1 + (input_len+15)/SE_BUFFER_SIZE;

      if (in_buffer!=NULL) free(in_buffer);
      if (enc_out_buffer!=NULL) free(enc_out_buffer);
      if (b64_result!=NULL) free(b64_result);

      in_buffer = (char *)malloc(times*SE_BUFFER_SIZE*sizeof(char));
      in_buffer_size=times*SE_BUFFER_SIZE;
      
      enc_out_buffer = (char *)malloc(times*SE_BUFFER_SIZE*sizeof(char));
      enc_out_buffer_size = times*SE_BUFFER_SIZE;
      
      b64_result = (char *)malloc(times*SE_BUFFER_SIZE_B64*sizeof(char));
      b64_result_size = times*SE_BUFFER_SIZE_B64;
      
    }
    
    memset(in_buffer,'\0',in_buffer_size*sizeof(char));
    memset(enc_out_buffer,'\0',enc_out_buffer_size*sizeof(char));
    memset(b64_result,'\0',b64_result_size*sizeof(char));
    
    strncpy(in_buffer,string,in_buffer_size-1);
    
    padded_len = input_len%16==0 ? input_len : 16*(1+input_len/16);
    
    retval = blockEncrypt(&rijndael_OP[core][id], (uint8_t *)in_buffer,padded_len*8,(UINT8 *)enc_out_buffer);

    b64_enc_string = (char *)base64(enc_out_buffer,retval/8,&flen);
    strncpy(b64_result,b64_enc_string,b64_result_size-1);
    
    if (b64_enc_string!=NULL)
      free(b64_enc_string);
    
    return(b64_result);    
  }
  else {
    /* Return the unmodified argument */
    return string;
  }
  
}




/*static uint8_t m_key[MAX_INTERFACES][16];
static uint8_t m_pad[16];

#define CACHEBITS 20
#define CACHESIZE (1 << CACHEBITS)

//static uint32_t enc_cache[CACHESIZE];

static uint32_t *enc_cache = 0;
static uint32_t fullcache[2][2];*/



void panon_init_cache(crypto_ip * self) {
        if (self->enc_cache == 0) { 
                self->enc_cache = (uint32_t *)malloc(CACHESIZE * sizeof(uint32_t));
        }
        memset(self->enc_cache,0,(CACHESIZE * sizeof(uint32_t)));
        self->fullcache[0][0] = 0;
        self->fullcache[0][1] = 0;
        self->fullcache[1][0] = 0;
        self->fullcache[1][1] = 0;
}
static void cache_update(crypto_ip * self, uint32_t scan, int id, int core) {
        uint8_t rin_output[16];
        uint8_t rin_input[16];
        uint32_t orig_addr = 0;
        uint32_t result = 0;
        uint32_t first4bytes_pad, first4bytes_input;
        int pos;

        rte_memcpy(rin_input, self->m_pad, 16);
        first4bytes_pad = (((uint32_t) self->m_pad[0]) << 24) + 
                (((uint32_t) self->m_pad[1]) << 16 ) + 
                (((uint32_t) self->m_pad[2]) << 8) + 
                (uint32_t) self->m_pad[3];


        rte_memcpy(rin_input, self->m_pad, 16);
        orig_addr = (scan << (32 - CACHEBITS));
        result = 0;
        for (pos = 0; pos < CACHEBITS; pos++) {

                if (pos == 0) {
                        first4bytes_input = first4bytes_pad;
                } else {
                        first4bytes_input = 
                                ((orig_addr >> (32 - pos)) << (32 - pos)) |
                                ((first4bytes_pad << pos) >> pos);
                }
                rin_input[0] = (uint8_t) (first4bytes_input >> 24);
                rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
                rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
                rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

                blockEncrypt(&rijndael_OP[core][id], rin_input, 128, rin_output);

                result |= (rin_output[0] >> 7) << (31 - pos);
        }
        self->enc_cache[scan] = (result >> (32 - CACHEBITS));

}
static uint32_t lookup_cache(crypto_ip * self, uint32_t orig_addr, int id, int core) {
        uint32_t lookup_addr = (orig_addr >> (32 - CACHEBITS));
        if (self->enc_cache[lookup_addr] == 0) {
                cache_update(self, lookup_addr, id, core);
        }
        return self->enc_cache[lookup_addr];
}

void panon_init(crypto_ip * self, const char * key, int id, int core) {
        // initialise the 128-bit secret key
        rte_memcpy(self->m_key[id], key, 16);
        // initialise the Rijndael cipher
	rijndael_init(&rijndael_OP[core][id], ECB, Encrypt, (const UINT8*)key, Key16Bytes,0);
        blockEncrypt(&rijndael_OP[core][id], (const UINT8*)key + 16, 128, self->m_pad);
        panon_init_cache(self);
}
void panon_init_decrypt(crypto_ip * self, const uint8_t * key, int id, int core) {
        rte_memcpy(self->m_key, key, 16);
        rijndael_init(&rijndael_OP[core][id], ECB, Decrypt, key, Key16Bytes,0);
        blockEncrypt(&rijndael_OP[core][id], key + 16, 128, self->m_pad);
}

uint32_t pp_anonymize(crypto_ip * self, const uint32_t orig_addr, int id, int core) {
        uint8_t rin_output[16];
        uint8_t rin_input[16];

        uint32_t result = 0;
        uint32_t first4bytes_pad, first4bytes_input;
        int pos;

        rte_memcpy(rin_input, self->m_pad, 16);
        first4bytes_pad = (((uint32_t) self->m_pad[0]) << 24) + 
                (((uint32_t) self->m_pad[1]) << 16 ) + 
                (((uint32_t) self->m_pad[2]) << 8) + 
                (uint32_t) self->m_pad[3];

        // For each prefix with length 0 to 31, generate a bit using the 
        // rijndael cipher, which is used as a pseudorandom function here. 
        // The bits generated in every round are combined into a pseudorandom 
        // one-time-pad.

        for (pos = 0; pos <= 31; pos++) {
                // Padding: The most significant pos bits are taken from orig_addr.
                // The other 128-pos bits are taken from m_pad. The variables 
                // first4bytes_pad and first4bytes_input are used to handle the annoying
                // byte order problem

                if (pos == 0) {
                        first4bytes_input = first4bytes_pad;
                } else {
                        first4bytes_input = ((orig_addr >> (32 - pos)) << (32 - pos)) |
                                ((first4bytes_pad << pos) >> pos);
                }
                rin_input[0] = (uint8_t) (first4bytes_input >> 24);
                rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
                rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
                rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

                // Encryption: The rijndael cipher is used as a pseudorandom function.
                // During each round, only the first bit of rin_output is used.
                blockEncrypt(&rijndael_OP[core][id], rin_input, 128, rin_output);

                // Combination: the bits are combined into a pseudorandom one-time-pad.
                result |= (rin_output[0] >> 7) << (31 - pos);
        }

        return result ^ orig_addr;
}


uint32_t cpp_anonymize(crypto_ip * self, const uint32_t orig_addr, int id, int core) {
        uint8_t rin_output[16];
        uint8_t rin_input[16];
        
        //uint32_t firstnbits;

        uint32_t result = 0;
        uint32_t first4bytes_pad, first4bytes_input;
        int pos;


        if (self->fullcache[0][0] == orig_addr) {
                return self->fullcache[0][1];
        } else if (self->fullcache[1][0] == orig_addr) {
                uint32_t tmp = self->fullcache[1][1];
                // move to "top" of "cache"
                self->fullcache[1][0] = self->fullcache[0][0];
                self->fullcache[1][1] = self->fullcache[0][1];
                self->fullcache[0][0] = orig_addr;
                self->fullcache[0][1] = tmp;
                return tmp;
        }
        
        rte_memcpy(rin_input, self->m_pad, 16);
        first4bytes_pad = (((uint32_t) self->m_pad[0]) << 24) + 
                (((uint32_t) self->m_pad[1]) << 16 ) + 
                (((uint32_t) self->m_pad[2]) << 8) + 
                (uint32_t) self->m_pad[3];

        // Look up the first CACHESIZE bits from enc_cache and start the 
        // result with this, then proceed

        //firstnbits = (uint32_t) orig_addr >> (32 - CACHEBITS);
        //result = (enc_cache[firstnbits] << (32 - CACHEBITS));


        result = (lookup_cache(self, orig_addr, id, core) << (32 - CACHEBITS));
        // For each prefix with length CACHEBITS to 31, generate a bit using the 
        // rijndael cipher, which is used as a pseudorandom function here. 
        // The bits generated in every round are combined into a pseudorandom 
        // one-time-pad.

        for (pos = CACHEBITS ; pos <= 31; pos++) {
                // Padding: The most significant pos bits are taken from orig_addr.
                // The other 128-pos bits are taken from m_pad. The variables 
                // first4bytes_pad and first4bytes_input are used to handle the annoying
                // byte order problem

                if (pos == 0) {
                        first4bytes_input = first4bytes_pad;
                } else {
                        first4bytes_input = ((orig_addr >> (32 - pos)) << (32 - pos)) |
                                ((first4bytes_pad << pos) >> pos);
                }
                rin_input[0] = (uint8_t) (first4bytes_input >> 24);
                rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
                rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
                rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

                // Encryption: The rijndael cipher is used as a pseudorandom function.
                // During each round, only the first bit of rin_output is used.
                blockEncrypt(&rijndael_OP[core][id], rin_input, 128, rin_output);

                // Combination: the bits are combined into a pseudorandom one-time-pad.
                result |= (rin_output[0] >> 7) << (31 - pos);
        }
        
        self->fullcache[1][0] = self->fullcache[0][0];
        self->fullcache[1][1] = self->fullcache[0][1];
        self->fullcache[0][0] = orig_addr;
        self->fullcache[0][1] = result ^ orig_addr;
        
        return result ^ orig_addr;
}

uint32_t anonymize(crypto_ip * self, const uint32_t orig_addr, int id, int core) {
        uint8_t rin_output[16]; 
        uint8_t rin_input[16]; 

        uint32_t result = 0;

        rte_memcpy(rin_input, self->m_pad, 16);

        rin_input[0] = (uint8_t) (orig_addr >> 24);
        rin_input[1] = (uint8_t) ((orig_addr << 8) >> 24);
        rin_input[2] = (uint8_t) ((orig_addr << 16) >> 24);
        rin_input[3] = (uint8_t) ((orig_addr << 24) >> 24);

        blockEncrypt(&rijndael_OP[core][id], rin_input, 128, rin_output);

        result = 0;
        result += (rin_output[0] <<24);
        result += (rin_output[1] <<16);
        result += (rin_output[2] <<8);
        result += (rin_output[3]);
        return result;
}






