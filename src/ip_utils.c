#include "ip_utils.h"


int internal_ip (struct in_addr adx)
{
    int i;

    for (i = 0; i < tot_nets; i++)
    {
            if ((adx.s_addr & net_mask[i]) == net_list[i].s_addr)
        {
            return 1;
        }
    }

    return 0;
}


int internal_ipv6 (struct in6_addr adx)
{
    return match_ipv6_net(adx,net_listv6,net_maskv6,tot_netsv6);
}

int match_ipv6_net(struct in6_addr adx, struct in6_addr *internal_list, int *mask_list, int list_size)
{
  static unsigned short int masks[] = { 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
  int i,full,partial,match;
//  char c[INET6_ADDRSTRLEN],d[INET6_ADDRSTRLEN];

  for (i = 0; i < list_size; i++)
    {
      if (mask_list[i]==0) 
	return 1;

//  inet_ntop(AF_INET6,&(adx),c,INET6_ADDRSTRLEN),
//  inet_ntop(AF_INET6,&(internal_net_listv6[i]),d,INET6_ADDRSTRLEN);
  
      full = mask_list[i]/8;
      partial = mask_list[i]%8;
      
      match = 0;
      if ( memcmp(&adx,&(internal_list[i]),full)!=0 )
       {
	 match = 0;
       }
      else if (partial!=0)
       {
	 if ( (adx.s6_addr[full] & masks[partial-1] ) == (internal_list[i].s6_addr[full] & masks[partial-1]) )
	   match = 1;
       }
      else
	match = 1;
      
      if (match == 1) 
         return 1;
    }

  return 0;
}


int ParseNetFile (  FILE *fp,
                    char *qualifier,
                    int max_entries, 
                    struct in_addr *CLASS_net_list,
                    struct in6_addr *CLASS_net_listv6,
                    int *CLASS_net_mask,
                    int *CLASS_net_maskv6,
                    int *tot_CLASS_nets,
                    int *tot_CLASS_netsv6) {

    char *line, *ip_string, *mask_string, *err;
    int i,j,k,len;
    int is_ipv4;
    long int mask_bits;
    unsigned int full_local_mask;
    struct in_addr mask2;
    char s[INET6_ADDRSTRLEN];

    (*tot_CLASS_nets) = 0;
    (*tot_CLASS_netsv6) = 0;
    i = 0; // File line
    j = 0; // Index for IPv4
    k = 0; // Index for IPv6
    while (1) {
        line = readline(fp, 1, 1);
	if (!line)
            break;

	len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';
        ip_string = line;

        if (j == max_entries) {
            printf ("ANON: Maximum number of %s IPv4 hosts/networks (%d) exceeded\n", qualifier, max_entries);
            return 0;
        }
        
        if (k == max_entries) {
           printf ("ANON: Maximum number of %s IPv6 hosts/networks (%d) exceeded\n", qualifier, max_entries);
            return 0;
        }

        is_ipv4 = 0;
        //single line format
        if (strchr(ip_string,'/'))
        {
            ip_string = strtok(ip_string,"/");
            mask_string = strtok(NULL,"/");

            if (!mask_string) {
                printf("ANON: Missing ip or network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }
            
            if (strchr(ip_string,':')) 
	     {  // IPv6 Address
                if (!inet_pton (AF_INET6,ip_string, &(CLASS_net_listv6[k]))) 
		  {
	            printf("ANON: Invalid ip address in %s config n.%d\n", qualifier, (i+1));
                    return 0;
                  }
	        is_ipv4 = 0;
	     }
	    else
	     {  // IPv4 Address
                if (!inet_pton (AF_INET,ip_string, &(CLASS_net_list[j])))
		 {
                   printf("ANON: Invalid ip address in %s config n.%d\n", qualifier, (i+1));
                   return 0;
	         }
	        is_ipv4 = 1;
             }

            //network mask as a single number
            if (!strchr(mask_string,'.'))
            { 
                err = NULL;
                mask_bits = strtol(mask_string, &err, 10);
		if (is_ipv4==1)
		 {
                   if (*err || mask_bits < 0 || mask_bits > 32) {
                      printf("ANON: Invalid network mask in %s config n.%d\n", qualifier, (i+1));
                      return 0;
		    }
                   else if (mask_bits==0)
	            {
                      printf("ANON: Warning: IPv4 mask set to 0 bits in %s config n.%d\n\tAny IPv4 address will be considered internal\n",
		         qualifier, (i+1));
		      CLASS_net_list[j].s_addr = 0; 
	            }
	            
                   if (CLASS_net_list[j].s_addr == 0)
                     full_local_mask = 0;
                   else
                     full_local_mask = 0xffffffff << (32 - mask_bits);

                   sprintf(s,"%d.%d.%d.%d",
                      full_local_mask >> 24,
                      (full_local_mask >> 16)  & 0x00ff,
                      (full_local_mask >> 8 ) & 0x0000ff,
                      full_local_mask & 0xff);
                   // inet_aton (s, &(CLASS_net_mask2[j]));
                   CLASS_net_mask[j] = inet_addr(s);
	           CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
		 }
		else
		 {
                   if (*err || mask_bits < 0 || mask_bits > 128) {
                     printf("ANON: Invalid network mask in %s config n.%d\n", qualifier, (i+1));
                     return 0;
                     }
                   else if (mask_bits>64 && mask_bits!=128)
	            {
                      printf("ANON: Warning: IPv6 mask should not exceed 64 bits in %s config n.%d\n", qualifier, (i+1));
	              // mask_bits=64;
	            }
                   else if (mask_bits==0)
	            {
                      printf("ANON: Warning: IPv6 mask set to 0 bits in %s config n.%d\n\tAny IPv6 address will be considered internal\n",
		         qualifier, (i+1));
	            }

                   CLASS_net_maskv6[k] = mask_bits;
		  }
            }
            //mask in dotted format
            else if (is_ipv4==1)
            {
                if (!inet_aton (mask_string, &mask2)) {
                    printf("ANON: Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                    return 0;
                }
                CLASS_net_mask[j] = inet_addr (mask_string);
	        CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            }
            else
	    {
               printf("ANON: Invalid IPv6 network mask in %s config n.%d\n", qualifier, (i+1));
               return 0;
	    }
        }
        //old format
        else
        {
            if (!inet_aton (ip_string, &(CLASS_net_list[j]))) {
                printf("ANON: Invalid IPv4 address in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }

            mask_string = readline(fp, 1, 1);
            if (!mask_string){
                printf("ANON: Missing IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }

            len = strlen(mask_string);
            if (mask_string[len - 1] == '\n')
                mask_string[len - 1] = '\0';
            if (!inet_aton (mask_string, &mask2)) {
                printf("ANON: Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i+1));
                return 0;
            }
            CLASS_net_mask[j] = inet_addr (mask_string);
	    CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            is_ipv4 = 1;
        }
       if (VERBOSE > 0)
        {
	  if (is_ipv4==1)
	   {
	    mask2.s_addr = CLASS_net_mask[j];
            printf ("ANON: Adding: %s as %s ",
                    inet_ntoa (CLASS_net_list[j]),qualifier);
            printf ("with mask %s (%u)\n", 
                    inet_ntoa (mask2),
                    CLASS_net_mask[j]);
	   }
	   else
	   {
	    inet_ntop (AF_INET6,&(CLASS_net_listv6[k]),s,INET6_ADDRSTRLEN);
            printf ("ANON: Adding: %s as %s ",s,qualifier);
            printf ("with mask %u\n",
                    CLASS_net_maskv6[k]);
	   }
        }
        
        if (is_ipv4==1)
 	 {
           (*tot_CLASS_nets)++;
	   j++;
	 }
	 else
	 {
           (*tot_CLASS_netsv6)++;
	   k++;
	 }
        i++;
    }
    return 1;
}

char * readline(FILE *fp, int skip_comment, int skip_void_lines) {
    static char *buf = NULL;
    static int buf_size = 0;
    static int next_pos = 0;
    char *tmp, curr_c;
    int comment_started = 0;

    if (buf == NULL) {
        buf = malloc(BUF_SIZE * sizeof(char));
        buf_size = BUF_SIZE;
        next_pos = 0;
    }

    buf[0] = '\0';
    next_pos = 0;
    while (1) {
        if (next_pos + 1 == buf_size) {
            buf_size += BUF_SIZE;
            tmp = malloc(buf_size * sizeof(char));
            strcpy(tmp, buf);
            free(buf);
            buf = tmp;
        }
        curr_c = fgetc(fp);
	if (feof(fp)) {
            buf[next_pos] = '\0';
            break;
        }

        comment_started |= skip_comment && (curr_c == '#');
        if (!comment_started || curr_c == '\n') {
            buf[next_pos] = curr_c;
            buf[next_pos + 1] = '\0';
            next_pos++;
        }

        if (curr_c == '\n') {
            if (buf[0] == '\n' && skip_void_lines) {
                buf[0] = '\0';
                next_pos = 0;
                comment_started = 0;
                continue;
            }
            else
                break;
       }
    }

    if (buf[0] == '\0')
        return NULL;
    return buf;
}





