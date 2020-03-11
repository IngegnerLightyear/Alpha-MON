#include "traffic_anon.h"
#include "process_packet.h"
//#include "traffic_anon.h"

//#include <semaphore.h>

//sem_t mutex;

/* All data structure initialization must be here */
void process_packet_init(int nb_sys_core)
{
    int cnt=0;
    for(int i=0; i<MAX_INTERFACES; i++)
    {
    	if (out_interface[i].anon_ip_enabled == 1)
        {
        	if ( strcmp(out_interface[i].anon_ip_key_mode, "static" ) == 0  )
            {
                for(int j=0; j<nb_sys_core; j++)
            			initialize_crypto(&crypto_data[j][i] ,out_interface[i].anon_ip_key, i, j);
        	}
        	FILE * fp = fopen(out_interface[i].anon_subnet_file, "r"); 
            ParseNetFile (  fp,
                        "anonymized networks",
                        MAX_SUBNETS, 
                        net_list,
                        net_listv6,
                        net_mask,
                        net_maskv6,
                        &tot_nets,
                        & tot_netsv6);

        	fclose(fp);
    	}
    }
    proto_init(nb_sys_core);
}

/* Invoked per each packet */
void process_packet(struct rte_mbuf * packet, out_interface_sett interface_setting, int id, int core)
{
    int len;

    struct timespec tp, tp1;
    clockid_t clk_id = CLOCK_MONOTONIC_COARSE;
    clock_gettime(clk_id, &tp);
    len = rte_pktmbuf_data_len(packet);

    if ( VERBOSE > 0)
        printf("ANON: Packet at core %d, len: %d\n", rte_lcore_id(), len);

   process_packet_eth(packet, interface_setting, tp);
   process_packet_ip(packet, interface_setting, id, core, tp);
}

/* Anonymize ethernet */
void process_packet_eth (struct rte_mbuf * packet, out_interface_sett interface_setting, struct timespec tp)
{
    int len;
    struct ether_hdr *eth_hdr;

    len = rte_pktmbuf_data_len(packet); 
    eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);

    packet->l2_len = sizeof(*eth_hdr);

    if ( VERBOSE > 0)
    {
        len = rte_pktmbuf_data_len(packet);
        printf("ANON:    Len: %d\n", len);
        print_ether_addr("ANON:    eth src: ", &eth_hdr->s_addr);
        printf("\n");
        print_ether_addr("ANON:    eth dst: ", &eth_hdr->d_addr);
        printf("\n");
    } 

    /*if (interface_setting.anon_mac_enabled == 1){

	uint8_t *bytes = uint8_t[ETHER_ADDR_LEN];
	bytes = (uint8_t) tp.tv_sec;

        eth_hdr->s_addr = eth_hdr->d_addr = (struct ether_addr ) bytes;
        if ( VERBOSE > 0)
            printf("ANON:    MAC addresses timestamped\n");
    }
    else*/
    if (interface_setting.anon_mac_enabled == 1)
    {
        eth_hdr->s_addr = eth_hdr->d_addr = (struct ether_addr ) {'\0','\0','\0','\0','\0','\0'};
        if ( VERBOSE > 0)
            printf("ANON:    MAC addresses removed\n");
    }
}

/* Anonymize IP */
void process_packet_ip (struct rte_mbuf * packet, out_interface_sett interface_setting, int id, int core, struct timespec tp)
{
    int len;
    uint16_t ether_type;
    char buf[MAX_STR];
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in6_addr src_addr_6;
    struct in6_addr dst_addr_6;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr * ipv4_header;
    struct ipv6_hdr * ipv6_header;

    len = rte_pktmbuf_data_len(packet);
    eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
    ether_type = htons(eth_hdr->ether_type);

    /* Is IPv4 */
    if (ether_type == 0x0800)
    {
        ipv4_header = rte_pktmbuf_mtod_offset(packet, struct ipv4_hdr *, sizeof(struct ether_hdr) );
        packet->l3_len = sizeof(*ipv4_header);

        src_addr.s_addr = ipv4_header->src_addr;
        dst_addr.s_addr = ipv4_header->dst_addr;

        if ( VERBOSE > 0)
        {
            printf("ANON:    IPv4\n");
            printf("ANON:    from %s\n", inet_ntoa(src_addr));
            printf("ANON:    to   %s\n", inet_ntoa(dst_addr));
        }

        if (interface_setting.anon_ip_enabled == 1)
        {
            if ( strcmp(interface_setting.anon_ip_key_mode, "static" ) == 0  )
            {
                if (internal_ip(src_addr))
                {
                    src_addr.s_addr = retrieve_crypto_ip(&crypto_data[core][id], &src_addr, id, core);
		            ipv4_header->src_addr = src_addr.s_addr;
                }
                if (internal_ip(dst_addr))
                {
                    dst_addr.s_addr = retrieve_crypto_ip(&crypto_data[core][id], &dst_addr, id, core);
                    ipv4_header->dst_addr = dst_addr.s_addr;
                }

                if ( VERBOSE > 0)
                {
                    printf("ANON:    new from %s\n", inet_ntoa(src_addr));
                    printf("ANON:    new to   %s\n", inet_ntoa(dst_addr));
                }
            }
        }
        /* Apply K-anon */
        if(interface_setting.k_anon!=0)
            multiplexer_proto(ipv4_header, NULL,  packet, core, tp, id, interface_setting.k_anon, interface_setting.k_delta, &crypto_data[core][id]);
    }
    /* Is IPv6 */
    else if(ether_type == 0x86DD){

        ipv6_header = rte_pktmbuf_mtod_offset(packet, struct ipv6_hdr *, sizeof(struct ether_hdr) );

	packet->l3_len = sizeof(*ipv6_header);

	//memcpy(&src_addr_6.s6_addr, ipv6_header->src_addr, sizeof(src_addr_6.s6_addr));
        //memcpy(&dst_addr_6.s6_addr, ipv6_header->dst_addr, sizeof(dst_addr_6.s6_addr));
	rte_memcpy(&src_addr_6.s6_addr, ipv6_header->src_addr, sizeof(src_addr_6.s6_addr));
        rte_memcpy(&dst_addr_6.s6_addr, ipv6_header->dst_addr, sizeof(dst_addr_6.s6_addr));

        if ( VERBOSE > 0){
            printf("ANON:    IPv6\n");
            inet_ntop(AF_INET6, &src_addr_6, buf, MAX_STR);
            printf("ANON:    from %s\n", buf);
            inet_ntop(AF_INET6, &dst_addr_6, buf, MAX_STR);
            printf("ANON:    to   %s\n", buf);
        }

        if (interface_setting.anon_ip_enabled == 1){
            if ( strcmp(interface_setting.anon_ip_key_mode, "static" ) == 0  ){
                if (internal_ipv6(src_addr_6)){
		    //sem_wait(&mutex);
                    src_addr_6 = *retrieve_crypto_ipv6(&crypto_data[core][id], &src_addr_6, id, core);
                    //memcpy(ipv6_header->src_addr, &src_addr_6.s6_addr, sizeof(src_addr_6.s6_addr));
		    rte_memcpy(ipv6_header->src_addr, &src_addr_6.s6_addr, sizeof(src_addr_6.s6_addr));
		    //sem_post(&mutex);
		 }
                if (internal_ipv6(dst_addr_6)){
		    //sem_wait(&mutex);
                    dst_addr_6 = *retrieve_crypto_ipv6(&crypto_data[core][id], &dst_addr_6, id, core);
                    //memcpy(ipv6_header->dst_addr, &dst_addr_6.s6_addr, sizeof(dst_addr_6.s6_addr));
		    rte_memcpy(ipv6_header->dst_addr, &dst_addr_6.s6_addr, sizeof(dst_addr_6.s6_addr));
		    //sem_post(&mutex);
                }

		//multiplexer_proto(NULL, ipv6_header, packet, core, tp, interface_setting.k_anon, interface_setting.k_delta);

                if ( VERBOSE > 0){
                    inet_ntop(AF_INET6, &src_addr_6, buf, MAX_STR);
                    printf("ANON:    new from %s\n", buf);
                    inet_ntop(AF_INET6, &dst_addr_6, buf, MAX_STR);
                    printf("ANON:    new to   %s\n", buf);
                }
            }
        }
        /* Apply K-anon */
        // NOT FULLY SUPPORTED YET
        //if(interface_setting.k_anon!=0)
            //multiplexer_proto(ipv4_header, NULL,  packet, core, tp, id, interface_setting.k_anon, interface_setting.k_delta, &crypto_data[core][id]);
    }
}

