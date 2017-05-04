#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>

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
    struct bucket_entry entry[BUCKET_SIZE];
}bucket_list;

__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE];

__shared __export __addr40 __imem uint32_t ports[MAX_NUM_PUBLIC_IPS][2048];
__shared __export __imem uint32_t cur_port[MAX_NUM_PUBLIC_IPS] = { 1025, 1025, 1025, 1025, 1025, 1025};
__shared __export __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS] = {IP_ADDR(111,111,111,111),IP_ADDR(222,222,222,222),IP_ADDR(133,133,133,133),IP_ADDR(144,144,144,144),IP_ADDR(101,101,101,101),IP_ADDR(202,202,202,202)};
__shared __export __imem uint32_t num_used_public_ips = 4;
__shared __export __imem uint32_t cur_public_ip = 0;


/* Stats Counters */
volatile __declspec(i28.imem, shared, export) uint32_t cntr_before_port_assign = 0;
volatile __declspec(i28.imem, shared, export) uint32_t cntr_after_port_assign = 0;
volatile __declspec(i28.imem, shared, export) uint32_t cntr_port_not_assign = 0;
volatile __declspec(i28.imem, shared, export) uint32_t search_non_zero = 0;




int pif_plugin_get_public_port(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;

    __gpr uint32_t my_public_ip = cur_public_ip; /* TODO change to atomic read maybe */
    __xrw uint32_t my_cur_port_xrw;
    __xrw uint32_t my_cur_ip_xrw;
    __xrw uint32_t bit_to_set;
    __xwrite uint32_t min_port_num = MIN_CURRENT_PORT_VALUE;
    __xwrite uint32_t reset_cur_ip_wr = 0;
    __gpr uint32_t tmp_bit_to_set;

    uint32_t all_ports_used = 0;

    if (!pif_plugin_hdr_ipv4_present(headers)) {
        return PIF_PLUGIN_RETURN_DROP;
    }

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    pif_plugin_meta_set__state_meta__nat_ip(headers, ipv4->srcAddr);
    pif_plugin_meta_set__state_meta__nat_port(headers, tcp->srcPort);

    do
    {
        mem_incr32((__mem void *)&cntr_before_port_assign);
        mem_incr32(&all_ports_used);

        if (all_ports_used > 0xFFFF) {
           mem_incr32((__mem void *)&cntr_port_not_assign);
           return PIF_PLUGIN_RETURN_DROP;
        }

        ipv4->srcAddr = public_ips[my_public_ip];
        tcp->srcPort = cur_port[my_public_ip];

        /* get the in-use bit field offset, next port to test is in cur_port */
        my_cur_port_xrw = 1;
        mem_test_add(&my_cur_port_xrw, &cur_port[my_public_ip], 1 << 2);

        if (my_cur_port_xrw > MAX_CURRENT_PORT_VALUE-1)
            mem_write_atomic(&min_port_num, &cur_port[my_public_ip], 1 << 2);

        /* If we have a valid port number, try to set in_use */
        CALC_BIT_TO_SET_CLR(bit_to_set, my_cur_port_xrw);
        tmp_bit_to_set = bit_to_set;
        mem_test_set(&bit_to_set, &ports[my_public_ip][my_cur_port_xrw/32], 1 << 2);
    } while (bit_to_set&tmp_bit_to_set == 0x01);

    mem_incr32((__mem void *)&cntr_after_port_assign);


    /* Incr IP for next NAT - Which one is better? */

    if (num_used_public_ips > 1) {
        my_public_ip +=1;
        if (my_public_ip > num_used_public_ips-1)
            my_public_ip = 0;
        my_cur_ip_xrw = my_public_ip;
        mem_write_atomic(&my_cur_ip_xrw, &cur_public_ip, 1 << 2);
    }

    /* Incr IP for next NAT - Which one is better? */
    /*
    if (cur_public_ip < num_used_public_ips - 1)
        mem_incr32(&cur_public_ip);
    else
        mem_write_atomic(&reset_cur_ip_wr, &cur_public_ip, 4);
    */

    //TODO: clear flowcache entry for this flow so that another action happens based on updated state. (bump rule version? - wouldn't want to clear whole flowcash)


    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {

    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    volatile uint32_t hash_value;
    uint32_t  hash_key[3];
    __xread uint32_t hash_key_r[3];
    __addr40 bucket_entry_info *b_info;

    uint32_t i = 0;
    int found = 0;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    /* TODO: Add another field to indicate direction ?*/
    hash_key[0] = ipv4->srcAddr;
    hash_key[1] = ipv4->dstAddr;
    hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;

    //TODO: Change to toeplitz hash (what is secret key?):
    //hash_value = hash_toeplitz(&hash_key,sizeof(hash_key),);

    //hash_value = hash_me_crc32((void *)hash_key,sizeof(hash_key), 10);
    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);
    hash_value &= (0x0000FFFF);


    for (;i<BUCKET_SIZE;i++) {
        mem_read_atomic(hash_key_r, state_hashtable[hash_value].entry[i].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */


        if (hash_key_r[0] == 0)
            continue;

        //memcmp(); ??
        if (hash_key_r[0] == hash_key[0] &&
            hash_key_r[1] == hash_key[1] &&
            hash_key_r[2] == hash_key[2] ) { /* && hash_key_r[0] != 0 ????? */
            b_info = &state_hashtable[hash_value].entry[i].bucket_entry_info_value;
            found = 1;
            break;
        }
    }

    if (found) {
        __xrw uint32_t count;

        /* Are these still needed on P4 side? State is needed on P4 side */
        pif_plugin_meta_set__state_meta__state(headers, b_info->state);
        pif_plugin_meta_set__state_meta__ip(headers, b_info->ip);
        pif_plugin_meta_set__state_meta__port(headers, b_info->port);
        pif_plugin_meta_set__state_meta__hit_count(headers, b_info->hit_count);

        count = 1;
        mem_test_add(&count,&b_info->hit_count, 1 << 2);
        if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */
            count = 2;
            mem_add32(&count,&b_info->hit_count, 1 << 2);
        } else if (count == 0xFFFFFFFF) {
            mem_incr32(&b_info->hit_count);
        }
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}



int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {

    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    volatile uint32_t update_hash_value;
    uint32_t update_hash_key[3];
    volatile uint32_t response_hash_value;
    uint32_t response_hash_key[3];
    uint32_t pvtIP;
    uint16_t pvtPort;

    __addr40 __emem bucket_entry_info *b_info;
    __xwrite bucket_entry_info tmp_b_info;
    __addr40 uint32_t *key_addr;
    __xrw uint32_t key_val_rw[3];

    uint32_t i = 0;
    uint32_t j = 0;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    /* TODO: Add another field to indicate direction ?*/
    pvtIP = pif_plugin_meta_get__state_meta__nat_ip(headers);
    pvtPort = pif_plugin_meta_get__state_meta__nat_port(headers);
    update_hash_key[0] = pvtIP;
    update_hash_key[1] = ipv4->dstAddr;
    update_hash_key[2] = (pvtPort << 16) | tcp->dstPort;

    key_val_rw[0] = pvtIP;
    key_val_rw[1] = ipv4->dstAddr;
    key_val_rw[2] = (pvtPort << 16) | tcp->dstPort;


    //TODO: Change CRC to toeplitz (what is secret key?):
    //update_hash_value = hash_toeplitz();
    //response_hash_value = hash_toeplitz();
    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 1);
    update_hash_value &= (0x0000FFFF);

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


    tmp_b_info.state = 1;
    tmp_b_info.ip = ipv4->srcAddr;
    tmp_b_info.port = tcp->srcPort;
    tmp_b_info.public_private = 1;
    tmp_b_info.hit_count = 1;
    // tmp_b_info.hit_count_updated = 0xFFFFFFFF;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));
    //mem_write_atomic(update_hash_key, key_addr, sizeof(update_hash_key));

    response_hash_key[0] = ipv4->dstAddr;
    response_hash_key[1] = ipv4->srcAddr;
    response_hash_key[2] = (tcp->dstPort << 16) | tcp->srcPort;

    key_val_rw[0] = ipv4->dstAddr;
    key_val_rw[1] = ipv4->srcAddr;
    key_val_rw[2] = (tcp->dstPort << 16) | tcp->srcPort;

    response_hash_value = hash_me_crc32((void *)response_hash_key,sizeof(response_hash_key), 1);
    response_hash_value &= (0x0000FFFF);

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
    tmp_b_info.ip = pvtIP;
    tmp_b_info.port = pvtPort;
    tmp_b_info.public_private = 2;
    tmp_b_info.hit_count = 1;
    // tmp_b_info.hit_count_updated = 0xFFFFFFFF;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));
    //mem_write_atomic(response_hash_key, key_addr, sizeof(response_hash_key));

    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_clear_public_ports(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {

    __addr40 bucket_entry_info *b_info;
    __xread uint32_t hash_key_r[3];
    volatile uint32_t bit_to_clr;
    __xwrite uint32_t bit_to_clr_wr;
    uint32_t public_ip_indx = 0;
    volatile uint32_t clr_used_port_indx;
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
            if (b_info->hit_count == 0) {
                mem_incr32((__mem void *)&search_non_zero);
                continue;
            }

            if (b_info->hit_count == 0xFFFFFFFF) {
                __xwrite uint32_t clear_mem[8] = {0};
                /* private entry so b_info contains public ip/port for NAT */
                if (b_info->public_private == 1) {
                    CALC_BIT_TO_SET_CLR(bit_to_clr,b_info->port);
                    bit_to_clr_wr = bit_to_clr;
                    public_ip_indx = 0;
                    for (public_ip_indx;public_ip_indx<MAX_NUM_PUBLIC_IPS;public_ip_indx++) {
                        if (b_info->ip == public_ips[public_ip_indx]) {
                            break;
                        }
                    }
                    mem_bitclr(&bit_to_clr_wr,&ports[public_ip_indx][b_info->port/32],sizeof(bit_to_clr_wr));
                }
                //mem_write_atomic(clear_mem,&state_hashtable[i].entry[j],sizeof(clear_mem));
                mem_write_atomic(clear_mem,&state_hashtable[i].entry[j],sizeof(clear_mem)); /*Do this in one write...*/
                // mem_write_atomic(&clear_mem[8],&b_info->hit_count_updated,4);                    /*Do this in one write...*/

            } else {
                __xwrite uint32_t hit_count_update = 0xFFFFFFFF; //b_info->hit_count;
                mem_write_atomic(&hit_count_update,&b_info->hit_count,sizeof(hit_count_update));
            }
        }
    }
    return PIF_PLUGIN_RETURN_DROP;
}
