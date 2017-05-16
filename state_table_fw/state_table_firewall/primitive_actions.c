#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>

#define IP_ADDR(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)

#define CALC_BIT_TO_SET_CLR(A,k) (A = (1 << (k%32)) )


#define MIN_CURRENT_PORT_VALUE  1025
#define MAX_CURRENT_PORT_VALUE  0xFFFF
#define MAX_NUM_PUBLIC_IPS 16   /* 1048576 ports available */
#define BUCKET_SIZE 16
#define STATE_TABLE_SIZE 0xFFFFF /* 16777200 state table entries available */

typedef struct bucket_entry_info {
    uint32_t state;
    uint32_t ip;
    uint32_t port;
    uint32_t public_private; /* 0=none 1=public, 2=private */
    uint32_t hit_count; /* for timeouts */
} bucket_entry_info;

typedef struct bucket_entry {
    uint32_t key[3]; /* ip1, ip2, ports */
    bucket_entry_info bucket_entry_info_value;
}bucket_entry;


typedef struct bucket_list {
    // uint32_t ctl;
    struct bucket_entry entry[BUCKET_SIZE];
}bucket_list;

__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE];

__shared __export __addr40 __imem uint32_t ports[MAX_NUM_PUBLIC_IPS][2048];
__shared __export __imem uint32_t cur_port[MAX_NUM_PUBLIC_IPS] = { 1025, 1025, 1025, 1025, 1025, 1025};
__shared __export __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS] = {IP_ADDR(111,111,111,111),IP_ADDR(222,222,222,222),IP_ADDR(133,133,133,133),IP_ADDR(144,144,144,144),IP_ADDR(101,101,101,101),IP_ADDR(202,202,202,202)};
__shared __export __imem uint32_t num_used_public_ips = 4;
__shared __export __imem uint32_t cur_public_ip = 0;


/* Stats Counters */
volatile __declspec(i28.imem, shared, export) uint32_t int_ext_hits = 0;
volatile __declspec(i28.imem, shared, export) uint32_t bucket_full_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t bucket_full_1_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t no_port_available_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t never_found_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t not_ipv4_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t ext_int_drop = 0;
volatile __declspec(i28.imem, shared, export) uint32_t controller_pkt_drop = 0;


int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers,
                        MATCH_DATA_T *match_data)
{

    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    volatile uint32_t update_hash_value;
    uint32_t update_hash_key[3];
    volatile uint32_t response_hash_value;
    uint32_t response_hash_key[3];
    uint32_t pubIP;
    uint16_t pubPort;

    __addr40 __emem bucket_entry_info *b_info;
    __xwrite bucket_entry_info tmp_b_info;
    __addr40 uint32_t *key_addr;
    __xrw uint32_t key_val_rw[3];

    uint32_t i = 0;
    
    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    /* TODO: Add another field to indicate direction ?*/
    update_hash_key[0] = ipv4->srcAddr;
    update_hash_key[1] = ipv4->dstAddr;
    update_hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;

    key_val_rw[0] = ipv4->srcAddr;
    key_val_rw[1] = ipv4->dstAddr;
    key_val_rw[2] = (tcp->srcPort << 16) | tcp->dstPort;

    //TODO: Change CRC to toeplitz:
    //update_hash_value = hash_toeplitz();
    //response_hash_value = hash_toeplitz();
    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 1);
    update_hash_value &= (STATE_TABLE_SIZE);

    for (;i<BUCKET_SIZE;i++) {
        if (state_hashtable[update_hash_value].entry[i].key[0] == 0) {
            b_info = &state_hashtable[update_hash_value].entry[i].bucket_entry_info_value;
            key_addr = state_hashtable[update_hash_value].entry[i].key;
            break;
        }
    }
    /* If bucket full, drop */
    if (i == BUCKET_SIZE)
        return PIF_PLUGIN_RETURN_DROP;


    pubIP = pif_plugin_meta_get__state_meta__ip(headers);
    pubPort = pif_plugin_meta_get__state_meta__port(headers);;

    tmp_b_info.state = 1;
    tmp_b_info.ip = pubIP;
    tmp_b_info.port = pubPort;
    tmp_b_info.public_private = 1;
    tmp_b_info.hit_count = 1;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));

    response_hash_key[0] = ipv4->dstAddr;
    response_hash_key[1] = pubIP;
    response_hash_key[2] = (tcp->dstPort << 16) | pubPort;

    key_val_rw[0] = ipv4->dstAddr;
    key_val_rw[1] = pubIP;
    key_val_rw[2] = (tcp->dstPort << 16) | pubPort;

    response_hash_value = hash_me_crc32((void *)response_hash_key,sizeof(response_hash_key), 1);
    response_hash_value &= (STATE_TABLE_SIZE);
  
    for (i=0;i<BUCKET_SIZE;i++) {
        if (state_hashtable[response_hash_value].entry[i].key[0] == 0) {
            b_info = &state_hashtable[response_hash_value].entry[i].bucket_entry_info_value;
            key_addr = state_hashtable[response_hash_value].entry[i].key;
            break;
        }
    }
    /* If bucket full, drop */
    if (i == BUCKET_SIZE)
        return PIF_PLUGIN_RETURN_DROP;
     

    tmp_b_info.state = 1;
    tmp_b_info.ip = ipv4->srcAddr;
    tmp_b_info.port = tcp->srcPort;
    tmp_b_info.public_private = 2;
    tmp_b_info.hit_count = 1;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_get_public_port(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;

    __gpr uint32_t my_public_ip = cur_public_ip;
    __xrw uint32_t my_cur_port_xrw;
    __xrw uint32_t my_cur_ip_xrw;
    __xrw uint32_t bit_to_set_xrw;
    __xwrite uint32_t min_port_num = MIN_CURRENT_PORT_VALUE;
    __xwrite uint32_t reset_cur_ip_wr = 0;
    __gpr uint32_t bit_to_set;

    uint32_t all_ports_used = 0;

    if (!pif_plugin_hdr_ipv4_present(headers)) {
        mem_incr32((__mem void *)&not_ipv4_drop);
        return PIF_PLUGIN_RETURN_DROP;
    }

    do
    {
        mem_incr32(&all_ports_used);

        if (all_ports_used > 0xFFFF) {
           mem_incr32((__mem void *)&no_port_available_drop);
           return PIF_PLUGIN_RETURN_DROP;
        }

        /* get the in-use bit field offset, next port to test is in cur_port */
        my_cur_port_xrw = 1;
        mem_test_add(&my_cur_port_xrw, &cur_port[my_public_ip], 1 << 2);

        if (my_cur_port_xrw > MAX_CURRENT_PORT_VALUE-1)
            mem_write_atomic(&min_port_num, &cur_port[my_public_ip], 1 << 2);

        /* If we have a valid port number, try to set in_use */
        CALC_BIT_TO_SET_CLR(bit_to_set, my_cur_port_xrw);
        bit_to_set_xrw = bit_to_set;
        mem_test_set(&bit_to_set_xrw, &ports[my_public_ip][my_cur_port_xrw/32], 1 << 2);

        if (!(bit_to_set&bit_to_set_xrw)) {           
            pif_plugin_meta_set__state_meta__ip(headers, public_ips[my_public_ip]);
            pif_plugin_meta_set__state_meta__port(headers, my_cur_port_xrw);
            break;
        }

    } while (1);

    if (num_used_public_ips > 1) {
        my_public_ip +=1;
        if (my_public_ip > num_used_public_ips-1)
            my_public_ip = 0;
        my_cur_ip_xrw = my_public_ip;
        mem_write_atomic(&my_cur_ip_xrw, &cur_public_ip, 1 << 2);
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {

    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    volatile uint32_t hash_value;
    uint32_t  hash_key[3];
    __xread uint32_t hash_key_r[3];
    __addr40 bucket_entry_info *b_info;

    uint32_t i;
    int found = 0;
    __xrw uint32_t first_packet_xrw = 1;
    int loopcount = 0;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    /* TODO: Add another field to indicate direction ?*/
    hash_key[0] = ipv4->srcAddr;
    hash_key[1] = ipv4->dstAddr;
    hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;

    //TODO: Change to toeplitz hash:
    //hash_value = hash_toeplitz(&hash_key,sizeof(hash_key),);
    //hash_value = hash_me_crc32((void *)hash_key,sizeof(hash_key), 10);
    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);
    hash_value &= (STATE_TABLE_SIZE);   
        
    for (i = 0; i < BUCKET_SIZE; i++) {
        mem_read_atomic(hash_key_r, state_hashtable[hash_value].entry[i].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */

        if (hash_key_r[0] == 0) {
            continue;
        }
        
        if (hash_key_r[0] == hash_key[0] &&
            hash_key_r[1] == hash_key[1] &&
            hash_key_r[2] == hash_key[2] ) { /* Hit */
            
            __xrw uint32_t count;

            b_info = &state_hashtable[hash_value].entry[i].bucket_entry_info_value;
            pif_plugin_meta_set__state_meta__ip(headers, b_info->ip);
            pif_plugin_meta_set__state_meta__port(headers, b_info->port);

            count = 1;
            mem_test_add(&count,&b_info->hit_count, 1 << 2);
            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
                count = 2;
                mem_add32(&count,&b_info->hit_count, 1 << 2);
            } else if (count == 0xFFFFFFFF) {
                mem_incr32(&b_info->hit_count);
            }
            mem_incr32((__mem void *)&int_ext_hits);        
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }
   
    if (pif_plugin_meta_get__state_meta__incoming_port(headers) == 1) {  /* Ext_Int_Miss -> Drop */
        mem_incr32((__mem void *)&ext_int_drop);
        return PIF_PLUGIN_RETURN_DROP;
    } else { /* Int_Ext_Miss -> Assign port and update state table */
 
                if (pif_plugin_get_public_port(headers, match_data) == PIF_PLUGIN_RETURN_DROP) { 
                    return PIF_PLUGIN_RETURN_DROP;
                }
            
                if (pif_plugin_state_update(headers, match_data) == PIF_PLUGIN_RETURN_DROP) {
                    return PIF_PLUGIN_RETURN_DROP;
                }
    } 
    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_clear_public_ports(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {

    __addr40 bucket_entry_info *b_info;
    __xread bucket_entry_info b_info_r;
    __xread uint32_t hash_key_r[3];
    __gpr uint32_t bit_to_clr;
    __xwrite uint32_t bit_to_clr_wr;
    uint32_t public_ip_indx = 0;
    __gpr uint32_t clr_used_port_indx;
    __xwrite uint32_t clr_used_port_indx_w = 0;
    uint32_t i = 0;
    uint32_t j = 0;

    for (i=0;i<STATE_TABLE_SIZE;i++) {
        for (j=0;j<BUCKET_SIZE;j++) {
            mem_read_atomic(hash_key_r, state_hashtable[i].entry[j].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */

            if (hash_key_r[0] == 0) {
                continue;
            }

            b_info = &state_hashtable[i].entry[j].bucket_entry_info_value;            
            mem_read_atomic(&b_info_r,b_info,sizeof(b_info_r));
            if (b_info_r.hit_count == 0) {
                continue;
            }

            if (b_info_r.hit_count == 0xFFFFFFFF) {
                __xwrite uint32_t clear_mem[8] = {0};                                

                /* private entry so b_info contains public ip/port for NAT */
                if (b_info_r.public_private == 1) {
                    CALC_BIT_TO_SET_CLR(bit_to_clr,b_info_r.port);
                    bit_to_clr_wr = bit_to_clr;
                    for (public_ip_indx=0;public_ip_indx<MAX_NUM_PUBLIC_IPS;public_ip_indx++) {
                        if (b_info_r.ip == public_ips[public_ip_indx]) {
                            break;
                        }
                    }
                    mem_bitclr(&bit_to_clr_wr,&ports[public_ip_indx][b_info_r.port/32],sizeof(bit_to_clr_wr));
                }                
                mem_write_atomic(clear_mem,&state_hashtable[i].entry[j],sizeof(clear_mem));                 

            } else {
                __xwrite uint32_t hit_count_update = 0xFFFFFFFF;
                mem_write_atomic(&hit_count_update,&b_info->hit_count,sizeof(hit_count_update));
            }
        }
    }
    mem_incr32((__mem void *)&controller_pkt_drop);
    return PIF_PLUGIN_RETURN_DROP;
}
