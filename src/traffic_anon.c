#include "traffic_anon.h"
#include <semaphore.h>


sem_t print_mutex;

/* Main function */
int main(int argc, char **argv)
{
    int ret;
    int i = 0;
    int exit = 0;

    sem_init(&print_mutex, 0, 1);

    /* Create handler for SIGTERM and SIGINT for CTRL + C closing */
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    /* Initialize DPDK enviroment with args, then shift argc and argv to get application parameters */
    ret = rte_eal_init(argc, argv);

    if (ret < 0) FATAL_ERROR("Cannot init EAL. Error: %s.", rte_strerror(rte_errno) );
    argc -= ret;
    argv += ret;

    /* Make standard output more silent */
    rte_log_set_global_level ( RTE_LOG_EMERG | RTE_LOG_ALERT | RTE_LOG_CRIT | RTE_LOG_ERR );

    /* Parse arguments (must retrieve the total number of cores, which core I am, and time engine to use) */
    ret = parse_args(argc, argv);
    if (ret < 0) FATAL_ERROR("Wrong arguments. Quitting.");

    /* Init Processing data structures*/
    process_packet_init((int)rte_lcore_count());

    /* Get number of ethernet devices */
    nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports <= 0) FATAL_ERROR("Cannot find ETH devices.");

    /* Get number of lcores */
    nb_sys_cores = rte_lcore_count();
    printf("ANON: System has %d core(s) and %d port(s)\n", nb_sys_cores, nb_sys_ports);

    /* Create mem pool, on the socket of the first interface */
    pktmbuf_pool = rte_pktmbuf_pool_create(MEMPOOL_NAME, mempool_elem_nb*20,
                                           MEMPOOL_CACHE_SZ, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                           rte_eth_dev_socket_id(0));

    pktmbuf_pool2 = rte_pktmbuf_pool_create(MEMPOOL_NAME2, mempool_elem_nb*20,
                                           MEMPOOL_CACHE_SZ, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
					   rte_eth_dev_socket_id(0));

    if (pktmbuf_pool == NULL || pktmbuf_pool2 == NULL)
        FATAL_ERROR("Cannot create cluster_mem_pool. Error: %s.", rte_strerror(rte_errno) );

    /* Operations needed for each ethernet device */
    for(i=0; i < nb_sys_ports; i++){
        if(used_ports[i] == 1)
		init_port(i);
    }



    /* ... and then loop in consumer */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);

    return 0;
}


/* Loop function, batch timing implemented */
static int main_loop(__attribute__((unused)) void * arg){

    struct rte_mbuf *pkts_burst[PKT_BURST_SZ], *copybufs[PKT_BURST_SZ];
    int i,  nb_rx, port_cnt = 0, ret = 0, k=0, j=0;
    int destination_port;
    int nb_istance = rte_lcore_id();
    uint64_t stats_rate = rte_get_tsc_hz();
    uint64_t old_time = 0;
    uint64_t new_time = 0;
    struct rte_eth_stats stat;
    char port_address [RTE_ETH_NAME_MAX_LEN];
    struct rte_eth_stats all_stats_old [MAX_INTERFACES];
    struct rte_mbuf *org_mbuf = NULL;
    int destination_port_cp;
    int dest_cnt;

    /* Print configuration parameters */
    sem_wait(&print_mutex);
    printf("In Interfaces:\n");
    for(port_cnt = 0; port_cnt<in_interface_cnt; port_cnt++)
    {
        printf("CHECK: Interface %d -> %s\n", in_interface[port_cnt].id, in_interface[port_cnt].address);
        printf("CHECK:	#out: %d\n", in_interface[port_cnt].n_out);
        for(dest_cnt=0; dest_cnt<in_interface[port_cnt].n_out; dest_cnt++)
            printf("CHECK:		%d\n", in_interface[port_cnt].out_port[dest_cnt]);
        printf("\n");
    }
    printf("\n");
    printf("Out Interfaces:\n");
    for (port_cnt = 0;port_cnt < nb_sys_ports; port_cnt++)
    {
        if(strcmp("static", out_interface[port_cnt].anon_ip_key_mode) == 0 || strcmp("null", out_interface[port_cnt].anon_ip_key_mode) == 0)
        {
            printf("CHECK: Interface %d\n", port_cnt);
            printf("CHECK:          anon_mac -> %d\n", out_interface[port_cnt].anon_mac_enabled);
            printf("CHECK:          anon_ip -> %d\n", out_interface[port_cnt].anon_ip_enabled);
            printf("CHECK:          anon_ip_key_mode -> %s\n", out_interface[port_cnt].anon_ip_key_mode);
            printf("CHECK:          anon_ip_key -> %s\n", out_interface[port_cnt].anon_ip_key);
            printf("CHECK:          anon_subnet_file -> %s\n", out_interface[port_cnt].anon_subnet_file);
            printf("CHECK:          engine -> %d\n", out_interface[port_cnt].engine);
            printf("CHECK:              dns -> %d\n", out_interface[port_cnt].dns);
            printf("CHECK:              tls -> %d\n", out_interface[port_cnt].tls);
            printf("CHECK:              http -> %d\n", out_interface[port_cnt].http);
            printf("CHECK:          alpha -> %d\n", out_interface[port_cnt].alpha);
            printf("CHECK:          delta -> %d\n", out_interface[port_cnt].delta);
            printf("\n");
        }
    }
    printf("\n");
    
    sem_post(&print_mutex);
    sleep(1);

    /* Wait to give a starting randomness start for interfaces */
    srand(nb_istance);
    sleep(rand()%1);
    
    /* Infinite loop */
    for (;;) {

        /* Loop on ports */
	for (port_cnt = 0; port_cnt < in_interface_cnt; port_cnt++)
	{
		nb_rx = 0;

		/* Read packets and decide the output port */
            	nb_rx = rte_eth_rx_burst(in_interface[port_cnt].id, nb_istance, pkts_burst, PKT_BURST_SZ);

		if(nb_rx > 0)
		{
			for(dest_cnt = 0; dest_cnt < in_interface[port_cnt].n_out; dest_cnt++)
			{
				destination_port = in_interface[port_cnt].out_port[dest_cnt];
				//No copy on last interface
				if(dest_cnt == in_interface[port_cnt].n_out - 1)
				{

					for(k = 0; k < nb_rx; k++)
					{
						process_packet(pkts_burst[k], out_interface[destination_port], destination_port, nb_istance);

						while ( rte_eth_tx_burst (destination_port, nb_istance, &pkts_burst[k], 1) < 1){}
						pkts_core[nb_istance] ++;
					}
                    //while ( rte_eth_tx_burst (destination_port, nb_istance, pkts_burst, nb_rx) < 1){}
                    //pkts_core[nb_istance] +=nb_rx;
                    
				}
				//Copy if NOT LAST interface
				else
				{
					for (k = 0; k < nb_rx; k++)
					{
							org_mbuf = pkts_burst[k];
							rte_prefetch0(rte_pktmbuf_mtod(org_mbuf, void *));
							struct rte_mbuf *mirror_mbuf = NULL;
							struct rte_mbuf **mirror_mbufs = &mirror_mbuf;
							struct rte_mbuf *copy_mbuf = NULL;
							//Deep Copy
							do
							{
								while((copy_mbuf = rte_pktmbuf_alloc(pktmbuf_pool2)) == NULL)
								{
									rte_pktmbuf_free(copy_mbuf);
									copy_mbuf = NULL;
									rte_pktmbuf_free(mirror_mbuf);
                                    mirror_mbuf = NULL;
									printf("Copy mbuf alloc: FREEING ** %d **\n", nb_istance);
									if(rte_mempool_full(pktmbuf_pool) == 1)
										printf("MEMPOOL FULL\n");
								}

								copy_mbuf->data_off = org_mbuf->data_off;
								copy_mbuf->data_len = org_mbuf->data_len;
								copy_mbuf->port = org_mbuf->port;
								copy_mbuf->vlan_tci = org_mbuf->vlan_tci;
								copy_mbuf->tx_offload = org_mbuf->tx_offload;
								copy_mbuf->hash = org_mbuf->hash;

								copy_mbuf->next = NULL;
								copy_mbuf->pkt_len = org_mbuf->pkt_len;
								copy_mbuf->nb_segs = org_mbuf->nb_segs;
								copy_mbuf->ol_flags = org_mbuf->ol_flags;
								copy_mbuf->packet_type = org_mbuf->packet_type;

								rte_memcpy(rte_pktmbuf_mtod(copy_mbuf, char *),
								rte_pktmbuf_mtod(org_mbuf, char *),
								org_mbuf->data_len);

								*mirror_mbufs = copy_mbuf;
								mirror_mbufs = &copy_mbuf->next;
							} while ((org_mbuf = org_mbuf->next) != NULL);
							copybufs[k] = mirror_mbuf;
							process_packet(copybufs[k], out_interface[destination_port], destination_port, nb_istance);
						      
						while ( rte_eth_tx_burst (destination_port, nb_istance, &copybufs[k], 1) < 1){}
                        pkts_core[nb_istance] ++;
					}
                    //while ( rte_eth_tx_burst (destination_port, nb_istance, &copybufs, nb_rx) < 1){}
                    //pkts_core[nb_istance] +=nb_rx;
				}
			}
		}
	}

        /* Prints stats, for each port */
        new_time = rte_get_tsc_cycles();
        if ( PRINT_STATS && nb_istance == 0 && new_time - old_time > stats_rate ){

            for (i = 0; i < nb_sys_ports; i++){    

                /* Get stats */
                uint64_t freq = rte_get_tsc_hz();
                rte_eth_stats_get(i, &stat);
                rte_eth_dev_get_name_by_port(i, port_address);

                /* Print RX */
                int packets = stat.ipackets - all_stats_old[i].ipackets;
                int missed = stat.imissed - all_stats_old[i].imissed;
                int errors = stat.ierrors - all_stats_old[i].ierrors;
                int tot = packets+missed+errors;
                int bytes = stat.ibytes - all_stats_old[i].ibytes;
                float rate_mbs = ((double)bytes+(packets*24))/(new_time-old_time)*freq/1000000*8;
                float rate_mps = ((double)packets)/(new_time-old_time)*freq/1000000;
                float perc_rx = tot != 0 ? ((double)(errors + missed))/tot*100 : 0;

                printf("Port %2d: PCI address: %s\n",
                               i,    port_address);
                printf("     Rx: Rate: %8.3f Mbps %0.3f Mpps ",
                                    rate_mbs, rate_mps) ;
                printf("Rx: %8ld Missed: %8ld Err: %8ld Tot: %8ld Perc Drop/Err: %6.3f%%",
                         packets,      missed,   errors,      tot,             perc_rx) ;

                /* Notify in case of losses */
                if (  (missed+errors > 0) )
                    printf (" <--LOSING--");
                else
                    printf ("            ");
                printf("\n");

                /* Print TX */
                int opackets = stat.opackets - all_stats_old[i].opackets;
                int oerrors = stat.oerrors - all_stats_old[i].oerrors;
                int otot = opackets+oerrors;
                int obytes = stat.obytes - all_stats_old[i].obytes;
                float orate_mbs = ((double)obytes+(opackets*24))/(new_time-old_time)*freq/1000000*8;
                float orate_mps = ((double)opackets)/(new_time-old_time)*freq/1000000;
                float perc_tx = otot != 0 ? ((double)(oerrors))/otot*100 : 0;

                printf("     Tx: Rate: %8.3f Mbps %0.3f Mpps ",
                                   orate_mbs, orate_mps);
                printf("Tx: %8ld                  Err: %8ld Tot: %8ld      Perc Err: %6.3f%%\n",
                        opackets,                   oerrors,     otot,               perc_tx);

                all_stats_old[i] = stat;    
            }

            printf("\n");
            
            /* Handle interactive shell */
            if (INTERACTIVE_SHELL>0){
                for (i=0; i<nb_sys_ports*3 + 1; i++)
                    printf("\033[1A");
            } 

        old_time = new_time;
        }
    }

    return 0;
}


/* Signal handling function */
static void sig_handler(int signo)
{
    int i;
    char port_address [RTE_ETH_NAME_MAX_LEN];
    struct rte_eth_stats stat;

    if (rte_lcore_id() == 0){

        /* Handle interactive shell */
        if (INTERACTIVE_SHELL>0){
            for (i=0; i<nb_sys_ports*3 + 1; i++)
                printf("\n");
        } 

        /* Print Final Stats */
        printf ("\nShutting down...\n");
        
        /* By port */
        for (i=0; i<nb_sys_ports; i++){
            rte_eth_dev_get_name_by_port(i, port_address);
            rte_eth_stats_get(i, &stat);
            printf("Port %2d: PCI address: %s\n", i, port_address);
            printf("     Rx: %8ld Missed: %8ld Err: %8ld Tot: %8ld Perc Drop/Err: %6.3f%%\n",
                        stat.ipackets, stat.imissed, stat.ierrors,
                        stat.ipackets + stat.imissed + stat.ierrors,
                        ((double)(stat.imissed + stat.ierrors))/(stat.ipackets+stat.imissed+stat.ierrors)*100);

            printf("     Tx: %8ld                  Err: %8ld Tot: %8ld      Perc Err: %6.3f%%\n",
                        stat.opackets, stat.oerrors,
                        stat.opackets + stat.oerrors,
                        ((double)(stat.oerrors))/(stat.opackets + stat.oerrors)*100);

        }

        /* By core */
        printf ("\n");
        for (i=0; i<nb_sys_cores;i++){
            printf("Core %2d: processed packets: %8ld\n", i, pkts_core[i]);

        }
    }

    exit(0);    
}

/* Init each port with the configuration contained in the structs. Every interface has nb_sys_cores queues */
static void init_port(int i) {
        int j;
        int ret;
        uint8_t rss_key [40];
        char pci_address[10];
        char port_address [RTE_ETH_NAME_MAX_LEN];
        uint16_t nb_rxd = RX_QUEUE_SZ;
        uint16_t nb_txd = TX_QUEUE_SZ;
        struct rte_eth_link link;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_rss_conf rss_conf;

        /* Retreiving and printing device infos */
        rte_eth_dev_get_name_by_port(i, port_address);
        printf("ANON: Port %i - Address: %s\n", i, port_address);

        rte_eth_dev_info_get(i, &dev_info);
        if (dev_info.max_rx_queues < nb_sys_cores)
            FATAL_ERROR("Every interface must have a queue on each core, but this is not supported. You have %d cores, but can setup %d queues.\n", nb_sys_cores, dev_info.max_rx_queues);

        printf("ANON:     Driver name: %s\nANON:     Max rx queues: %d\nANON:     Max tx queues: %d\n",
                dev_info.driver_name, dev_info.max_rx_queues, dev_info.max_tx_queues);

        /* Add, if supported, DEV_TX_OFFLOAD_MBUF_FAST_FREE */
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        /* Decide the seed to give the port, by default use the classical symmetrical*/
        port_conf.rx_adv_conf.rss_conf.rss_key = rss_seed;

        /* Configure device with 'nb_sys_cores' rx queues and 1 tx queue */
        ret = rte_eth_dev_configure(i, nb_sys_cores, nb_sys_cores, &port_conf);
        if (ret < 0) FATAL_ERROR("Error configuring the port. Error: %s.", rte_strerror(rte_errno) );

        /* Check the size of queues */
        ret = rte_eth_dev_adjust_nb_rx_tx_desc(i, &nb_rxd, &nb_txd);
        if (ret < 0) FATAL_ERROR("Error adjusting queue numbers. Error: %s.", rte_strerror(rte_errno) );

        /* For each RX queue in each NIC */
        for (j = 0; j < nb_sys_cores; j++){
            /* Configure rx queue j of current device on current NUMA socket.
               It takes elements from the mempool */

            rte_eth_dev_info_get(i, &dev_info);
            ret = rte_eth_rx_queue_setup(i, j, RX_QUEUE_SZ,  rte_eth_dev_socket_id ( i ),
                                        &dev_info.default_rxconf, pktmbuf_pool);
            if (ret < 0) FATAL_ERROR("Error configuring receiving queue. Error: %s.", rte_strerror(rte_errno) );

            /* Configure mapping [queue] -> [element in stats array] */
            ret = rte_eth_dev_set_rx_queue_stats_mapping     (i, j, j );
            if (ret < 0) printf("ANON: [Warning] Error configuring receiving queue stats\n");


            /* Configure tx queue*/
            ret = rte_eth_tx_queue_setup(i, j, TX_QUEUE_SZ, rte_eth_dev_socket_id ( i ), &tx_conf);
            if (ret < 0) FATAL_ERROR("Error configuring transmitting queue. Error: %s.",rte_strerror(rte_errno));

            /* Configure mapping [queue] -> [element in stats array] */
            ret = rte_eth_dev_set_tx_queue_stats_mapping     (i, j, j );
            if (ret < 0) printf("ANON: [Warning] Error configuring transmitting queue stats\n");
        }

        /* Start device */        
        ret = rte_eth_dev_start(i);
        if (ret < 0) FATAL_ERROR("Cannot start port. Error: %s.", rte_strerror(rte_errno) );

        /* Enable receipt in promiscuous mode for an Ethernet device */
        rte_eth_promiscuous_enable(i);

        /* Print link status */
        rte_eth_link_get_nowait(i, &link);
        if (link.link_status) printf("ANON:     Link Up - speed %u Mbps - %s\n",
                                     (unsigned)link.link_speed,(link.link_duplex == ETH_LINK_FULL_DUPLEX)?
                                     ("full-duplex") : ("half-duplex\n"));
        else            printf("ANON:     Port %d Link Down\n",i);

        /* Print RSS support */
        rss_conf.rss_key = rss_key;
        ret = rte_eth_dev_rss_hash_conf_get (i,&rss_conf);
        if (ret == 0) printf("ANON:     Device supports RSS\n");
            else printf("ANON:     Device DOES NOT support RSS\n");
}

static int parse_args(int argc, char **argv)
{
    int option;
    
    /* Retrive arguments */
    while ((option = getopt(argc, argv,"c:")) != -1) {
        switch (option) {
            case 'c' :  strcpy(ini_file, optarg);
                        break;
            default: return -1; 
        }
    }

    /* Parse INI */
    printf("ANON: Parsing INI File: %s\n", ini_file);
    if (ini_parse(ini_file, parse_ini, NULL) < 0) {
        printf("Can't load ini\n");
        return -1;
    }

    return 0;
}

static int parse_ini(void* user, const char* section, const char* name,
                   const char* value)
{
    int ret;
    int found = 0;
    uint16_t port_in = -1;
    uint16_t port_out = -1;

printf("CHECK:  section %s, name %s\n", section ,name);

        if (strcmp(section, "general") == 0)
        {
                if (strcmp(name, "mempool_elem_nb") == 0)
                {
                        printf ("ANON:     [%s] %s: %s\n", section,name,value);
                        mempool_elem_nb = atoi(value);
                }
                else if(strcmp(name, "num_config") == 0)
                {
                        printf ("ANON:     [%s] %s: %s\n", section,name,value);
                        config = malloc(atoi(value) * sizeof(out_interface_sett));
                }
        }
        else if (strcmp(section, "interfaces_mappings") == 0)
        {
                ret = rte_eth_dev_get_port_by_name(name, &port_in);
                ret = rte_eth_dev_get_port_by_name(value, &port_out);
                used_ports[port_in] = 1;
                used_ports[port_out] = 1;
                for(int i = 0; i <= in_interface_cnt; i++)
                {
                        if(in_interface[i].id == port_in && in_interface_cnt != 0)
                        {
                                found = 1;
                                in_interface[i].out_port[in_interface[i].n_out] = port_out;
                                in_interface[i].n_out++;
                                break;
                        }
                }
                if(found == 0 || in_interface_cnt == 0)
                {
                        in_interface[in_interface_cnt].id = port_in;
                        strcpy(in_interface[in_interface_cnt].address, name);
                        in_interface[in_interface_cnt].out_port[in_interface[in_interface_cnt].n_out] = port_out;
                        in_interface[in_interface_cnt].n_out++;
                        in_interface_cnt++;
                }
                printf ("ANON:     Port [%s] in  -> Added\n", name);
                printf ("ANON:     Port [%s] out  -> Added\n", value);
        }

	else if (strstr(section, "group_") != NULL)
        {
                printf ("ANON:     Setting %s:\n", section);

                char str[100];
                strcpy(str, section);
                /* get pointer to start of string to be removed*/
                char *start = strstr(str, "group_");
                /* get pointer to end of string to be removed*/
                char *end = start + strlen("group_");
                /* move rest of string to former start of string to be removed*/
                memmove(start, start + strlen("group_"), strlen(end) + 1);

                ret = atoi(start);
                printf("CHECK:  config #%d\n", ret);
                /* MAC */
                if (strcmp(name, "anon_mac") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                config[ret].anon_mac_enabled = atoi(value);
                }
                /* IP */
                else if (strcmp(name, "anon_ip") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                config[ret].anon_ip_enabled = atoi(value);
                }else if (strcmp(name, "key_mode") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                strcpy(config[ret].anon_ip_key_mode, value);
                }else if (strcmp(name, "key") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                strcpy(config[ret].anon_ip_key, value);
                }else if (strcmp(name, "rotation_delay") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                config[ret].anon_ip_rotation_delay = atoi(value);
                }else if (strcmp(name, "anon_subnet_file") == 0) {
                printf ("ANON:     %s: %s\n", name,value);
                strcpy(config[ret].anon_subnet_file, value);
                }
		/* Protocols */
                else if (strcmp(name, "engine") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                config[ret].engine = atoi(value);
                }else if (strcmp(name, "dns") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                config[ret].dns = atoi(value);
                }else if (strcmp(name, "tls") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                config[ret].tls = atoi(value);
                }else if (strcmp(name, "http") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                config[ret].http = atoi(value);
                }
		/* K-anon */
		else if (strcmp(name, "alpha") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                config[ret].alpha = atoi(value);
                }
		else if (strcmp(name, "delta") == 0) {
                printf ("ANON:     [%s] %s: %s\n", section,name,value);
                if(config[ret].alpha!=0)
			if(atoi(value)>0)
				config[ret].delta = atoi(value);
			else{
				printf ("ERROR:     Wrong ALPHA/DELTA pair configuration\n");
                        	return 1;
			}
		else
			config[ret].delta = atoi(value);
                }
        }
        else if (strcmp(section, "interface_conf") == 0)
        {
                /* Interface address */
                ret = rte_eth_dev_get_port_by_name(name, &port_out);
                if(ret<0){
                        printf ("ERROR:     Unable to set interface\n");
                        return 1;
                        }
                memcpy(&out_interface[port_out], &config[atoi(value)], sizeof(config[atoi(value)]));
        }
        else if (strcmp(section, "end") == 0)
                free(config);

        return 1;

}
