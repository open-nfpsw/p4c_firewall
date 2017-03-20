#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <pif_registers.h>
//#include <nfp.h>
#include <nfp_intrinsic.h>
#include <nfp_override.h>

#include <pif_common.h>

// need the reglocked P4 pragma as you need exclusive access for the duration of the action
// there is a RTE api for configuring registers

#define IP_ADDR(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)

//6 public ips - enough?
#define MAX_NUM_PUBLIC_IPS 6

#define CALC_BIT_TO_SET_CLR(A,k) (A = (1 << (k%32)) )


#define MIN_CURRENT_PORT_VALUE  1025
#define MAX_CURRENT_PORT_VALUE  0xFFFF


__shared __export __addr40 __imem uint32_t ports[MAX_NUM_PUBLIC_IPS][2048];
__shared __export __imem uint32_t cur_port[MAX_NUM_PUBLIC_IPS] = { 1025, 1025, 1025, 1025, 1025, 1025};
__shared __export __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS] = {IP_ADDR(111,111,111,111),IP_ADDR(222,222,222,222),IP_ADDR(133,133,133,133),IP_ADDR(144,144,144,144),IP_ADDR(101,101,101,101),IP_ADDR(202,202,202,202)};
__shared __export __imem uint32_t num_used_public_ips = 4;
__shared __export __imem uint32_t cur_public_ip = 0;


int pif_plugin_get_public_port(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;

//    uint32_t lookup_state_index;

    __gpr uint32_t my_public_ip = cur_public_ip; /* TODO change to atomic read maybe */
//     __xrw uint32_t my_public_ip_rw;
//     __gpr uint32_t my_cur_port;
    __xrw uint32_t my_cur_port;
    __xrw uint32_t bit_to_set;
    __xwrite uint32_t min_port_num = MIN_CURRENT_PORT_VALUE;
    __xwrite uint32_t reset_cur_ip_wr = 0;

    if (!pif_plugin_hdr_ipv4_present(headers)) {
        return PIF_PLUGIN_RETURN_DROP;
    }

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);
//    lookup_state_index = pif_plugin_meta_get__openstate__lookup_state_index(headers);

    pif_plugin_meta_set__nat_meta__nat_ip(headers, ipv4->srcAddr);
    pif_plugin_meta_set__nat_meta__nat_port(headers, tcp->srcPort);

    do
    {
        /* get the in-use bit field offset, next availble port is in cur_port */
        my_cur_port = 1;
        mem_test_add(&my_cur_port, &cur_port[my_public_ip], 1 << 2);

        if (my_cur_port > MAX_CURRENT_PORT_VALUE)
            mem_write_atomic(&min_port_num, &cur_port[my_public_ip], 1 << 2); // TODO: will this work?

        /* We have a valid port number, try to set in_use */
        CALC_BIT_TO_SET_CLR(bit_to_set, my_cur_port);
        mem_test_set(&bit_to_set, &ports[my_public_ip][my_cur_port/32], 1 << 2);
    } while (bit_to_set == 0x01);


    ipv4->srcAddr = public_ips[my_public_ip];
    tcp->srcPort = cur_port[my_public_ip];

    /* Incr IP for next NAT */     
    /*IP should not realy 'add' without test since only one IP can be used? Old way should work for now? */
//    my_public_ip_rw = 1;
//    mem_test_add(&my_public_ip_rw, &cur_public_ip, 1 << 2);
    
    if (cur_public_ip < num_used_public_ips - 1)
        mem_incr32(&cur_public_ip);  // TODO also test add
    else
        mem_write_atomic(&reset_cur_ip_wr, &cur_public_ip, 4);
/*
    if (ipv4->srcAddr == IP_ADDR(0,0,0,0)) {
        return PIF_PLUGIN_RETURN_DROP;
    }
*/

    //clear flowcache entry for this flow so that another action happens based on updated state. (bump rule version? - wouldn't want to clear whole flowcash)

    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_clear_public_ports(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
    PIF_PLUGIN_clr_prts_hdr_T *clear_ports_hdr;

    __xwrite uint32_t bit_to_clr_wr;
    volatile uint32_t bit_to_clr;
    __mem __addr40 uint8_t *payload;
    __xread uint32_t payload_r[2];
    uint32_t public_ip_indx = 0;
    volatile uint32_t public_ip;
    volatile uint32_t clr_port;
    volatile uint32_t clr_used_port_indx;
    __xwrite uint32_t clr_used_port_indx_w = 0;
    uint32_t i=0;



    int payload_ctm_len;
    uint32_t mu_len, ctm_len;


    /* figure out how much data is in external memory vs ctm */
    if (pif_pkt_info_global.split) { /* payload split to MU */
        uint32_t sop; /* start of packet offset */
        sop = PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num);
        mu_len = pif_pkt_info_global.pkt_len - ((256 << pif_pkt_info_global.ctm_size) - sop);
    } else /* no data in MU */
        mu_len = 0;

    /* get the ctm byte count:
     * packet length - offset to parsed headers - byte_count_in_mu
     * Note: the parsed headers are always in ctm
     */
    payload_ctm_len = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off - mu_len;

//Code to get payload before #ifdef PKTIO_6_0_2
//not sure why it differs:
    /* Get a pointer to the ctm portion */
//    payload = pif_pkt_info_global.pkt_buf;
    /* point to just beyond the parsed headers */
//    payload += pif_pkt_info_global.pkt_pl_off;




#ifdef PKTIO_6_0_2
    payload = (__mem uint8_t *) pif_pkt_info_global.pkt_buf;
    payload += pif_pkt_info_global.pkt_pl_off;
#else
    payload = (__mem uint8_t *) pkt_ctm_ptr40(0,
                                              pif_pkt_info_global.p_pnum,
                                              pif_pkt_info_global.p_offset);
    payload += pif_pkt_info_spec.pkt_pl_off;
#endif
    payload += 2; /* move on 16 bits to get offset right for data */

    for (;i<payload_ctm_len;i+=12) {
        mem_read32(&payload_r, payload, sizeof(payload_r));
        public_ip = payload_r[0];
        clr_port = payload_r[1];
        payload += 8;
        mem_read32(&payload_r, payload, sizeof(payload_r));
        clr_used_port_indx = payload_r[0];
        payload += 4;
        public_ip_indx = 0;

        for (public_ip_indx;public_ip_indx<MAX_NUM_PUBLIC_IPS;public_ip_indx++) {
            if (public_ip == public_ips[public_ip_indx]) {
                break;
            }
        }
/*        if (public_ip != public_ips[public_ip_indx] || (public_ip != 0 && clr_port != 0) ) {
            continue;
            //return PIF_PLUGIN_RETURN_DROP;
        }
*/
        CALC_BIT_TO_SET_CLR(bit_to_clr,clr_port);
        bit_to_clr_wr = bit_to_clr;

        mem_bitclr(&bit_to_clr_wr,&ports[public_ip_indx][clr_port/32],sizeof(bit_to_clr_wr));
        //which one??
        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_hit_count[clr_used_port_indx], 4);
        //pif_register_reg_hit_count[clr_used_port_indx].value = 0;

        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_state[clr_used_port_indx], 4);
        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_public_ip[clr_used_port_indx], 4);
        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_public_port[clr_used_port_indx], 4);
        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_private_ip[clr_used_port_indx], 4);
        mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_private_port[clr_used_port_indx], 4);
    }

    /* same as above, but for mu. */
    if (mu_len) {
        payload = (__addr40 void *)((uint64_t)pif_pkt_info_global.muptr << 11);
        payload += (256 << pif_pkt_info_global.ctm_size);

        for (i=0;i<mu_len;i+=12) {
            mem_read32(&payload_r, payload, sizeof(payload_r));
            public_ip = payload_r[0];
            clr_port = payload_r[1];
            payload += 8;
            mem_read32(&payload_r, payload, sizeof(payload_r));
            clr_used_port_indx = payload_r[0];
            payload += 4;
            public_ip_indx = 0;

            for (public_ip_indx;public_ip_indx<MAX_NUM_PUBLIC_IPS;public_ip_indx++) {
                if (public_ip == public_ips[public_ip_indx]) {
                    break;
                }
            }
/*
            if (public_ip != public_ips[public_ip_indx] || (public_ip != 0 && clr_port != 0) ) {
                continue;
                //return PIF_PLUGIN_RETURN_DROP;
            }
*/

            CALC_BIT_TO_SET_CLR(bit_to_clr,clr_port);
            bit_to_clr_wr = bit_to_clr;

            mem_bitclr(&bit_to_clr_wr,&ports[public_ip_indx][clr_port/32],sizeof(bit_to_clr_wr));
            //which one??
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_hit_count[clr_used_port_indx], 4);
            //pif_register_reg_hit_count[clr_used_port_indx].value = 0;
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_state[clr_used_port_indx], 4);
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_public_ip[clr_used_port_indx], 4);
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_public_port[clr_used_port_indx], 4);
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_private_ip[clr_used_port_indx], 4);
            mem_write_atomic(&clr_used_port_indx_w, &pif_register_reg_private_port[clr_used_port_indx], 4);
        }
    }

    return PIF_PLUGIN_RETURN_DROP;
}
