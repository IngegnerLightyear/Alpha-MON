#ifndef TRAFFIC_ANON_H
#define TRAFFIC_ANON_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_version.h>

#include "ini.h"


/* Output parameters */
#define VERBOSE -1
#define PRINT_STATS 1
#define INTERACTIVE_SHELL 1
 

/* Macros and constants */
#define FATAL_ERROR(fmt, args...) rte_exit(EXIT_FAILURE, fmt "\n", ##args)
#define MEMPOOL_NAME "MEM_POOL"
#define MEMPOOL_NAME2 "MEM_POOL2"
#define MEMPOOL_CACHE_SZ 250      // MUST BE 0 WITH SCHED_DEADLINE, otherwise the driver wil crash !!
#define RX_QUEUE_SZ 4096        // The size of rx queue. Max is 4096.
#define TX_QUEUE_SZ 4096            // The size of tx queue. Max is 4096.
#define PKT_BURST_SZ 32            // Unfortunately it is 32 in DPDK 18
#define MAX_STR 256
#define MAX_INTERFACES 64
#define MAX_CORES 100


/* Function prototypes */
static int main_loop(__attribute__((unused)) void * arg);
static void sig_handler(int signo);
static void init_port(int i);
static int parse_args(int argc, char **argv);
static int parse_ini(void* user, const char* section, const char* name,
                   const char* value);

/* Global Vars */
static int nb_sys_ports;
static int nb_sys_cores;
char ini_file [MAX_STR];
static struct rte_mempool * pktmbuf_pool, *  pktmbuf_pool2;
static uint64_t pkts_core [MAX_CORES] = {0};
static int used_ports[MAX_INTERFACES];

typedef struct time_stat
{
	int n_pkt;
	int sum_time;
}time_stat;

time_stat time_pkt[MAX_CORES];

/* Configuration */
int mempool_elem_nb;

typedef struct out_interface_sett
{
  int anon_enabled;
  int anon_mac_enabled;
  int anon_ip_enabled;
  char anon_ip_key_mode [MAX_STR];
  char anon_ip_key [MAX_STR];
  int anon_ip_rotation_delay;
  char anon_subnet_file [MAX_STR];
  int engine;
  int dns;
  int tls;
  int http;
  int alpha;
  int delta;
} out_interface_sett;

typedef struct in_interface_sett
{
  int id;
  char address [MAX_STR];
  int n_out;
  int out_port [MAX_INTERFACES];
} in_interface_sett;

out_interface_sett *config;

out_interface_sett out_interface [MAX_INTERFACES];
in_interface_sett in_interface [MAX_INTERFACES];
static int in_interface_cnt = 0;


/* Struct for devices configuration for const defines see rte_ethdev.h */
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS, /* Enable RSS */
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key_len = 40, /* and the seed length. */
            .rss_hf = (ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP) , /* RSS mask*/
        }    
    }
};


/* Struct for configuring each rx queue. These are default values */
static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,   /* Ring prefetch threshold */
        .hthresh = 8,   /* Ring host threshold */
        .wthresh = 4,   /* Ring writeback threshold */
    },
    .rx_free_thresh = 32,    /* Immediately free RX descriptors */
};

/* Struct for configuring each tx queue. These are default values */
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,  /* Ring prefetch threshold */
        .hthresh = 0,   /* Ring host threshold */
        .wthresh = 0,   /* Ring writeback threshold */
    },
    .tx_free_thresh = 0,    /* Use PMD default values */
    .offloads = 0,  /* IMPORTANT for vmxnet3, otherwise it won't work */
    .tx_rs_thresh = 0,      /* Use PMD default values */
};


/* RSS symmetrical 40 Byte seed, according to
"Scalable TCP Session Monitoring with Symmetric Receive-side Scaling"
(Shinae Woo, KyoungSoo Park from KAIST)  */
static uint8_t rss_seed [] = {      0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
                                    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
                                    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
                                    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
                                    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a
};

#endif //TRAFFIC_ANON_H
