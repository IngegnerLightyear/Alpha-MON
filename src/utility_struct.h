
#include <time.h>

#define MAX_CLIENT 1000
#define FLOW_TABLE_SIZE 1000

/* Types */
struct lru
{
    int full;
    int client_hash;
    time_t timestamp;
    struct lru *prev;
    struct lru *next;
} lru;

typedef struct client
{
    int active;
    //int hash_val;
    int ipv;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    __uint128_t ipv6_src;
    __uint128_t ipv6_dst;
    uint16_t in_port;
    uint16_t out_port;
    uint8_t  protocol;
    time_t last_seen;
    struct lru *lru_ptr;
} client;

struct names
{
    int full;
    char name[100];
    char anon_name[100];
    int n_entry;
    int n_client;
    time_t oldest;
    struct names *prev;
    struct names *next;
    struct lru *head;
    struct lru *tail;
    client client_list[MAX_CLIENT];
} names;

typedef struct hash_struct
{
        int bitMap[FLOW_TABLE_SIZE];
        struct names table[FLOW_TABLE_SIZE];
} hash_struct;

typedef struct flow
{
    int ipv;
    uint32_t ipv4_src;
    uint32_t ipv4_dst;
    __uint128_t ipv6_src;
    __uint128_t ipv6_dst;
    uint16_t in_port;
    uint16_t out_port;
    uint8_t  protocol;
    time_t timestamp;
} flow;
