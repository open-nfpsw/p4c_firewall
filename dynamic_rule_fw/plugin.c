#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"



/*
 * Payload scan: search the payload for a string
 */

/* we define a static search string */
static __lmem uint8_t search_string[] = {'$'};

/* an exported variable counting number of detections
 * __export means will be able to access this memory from the host
 */
volatile __export __mem uint32_t search_detections = 0;
volatile __export __mem uint32_t search_ctm_detections = 0;
volatile __export __mem uint32_t search_mu_detections = 0;

/* Payload chunk size in LW (32-bit) and bytes */
#define CHUNK_LW 8
#define CHUNK_B (CHUNK_LW/4)

volatile __export __mem uint32_t pif_mu_len = 0;

int pif_plugin_payload_scan(EXTRACTED_HEADERS_T *headers,
                            MATCH_DATA_T *match_data)
{
    __mem uint8_t *payload;
    __xread uint32_t pl_data[CHUNK_LW];
    __lmem uint32_t pl_mem[CHUNK_LW];
    int search_progress = 0;
    int i, count, to_read;
    uint32_t mu_len, ctm_len;

    /* figure out how much data is in external memory vs ctm */

    if (pif_pkt_info_global.split) { /* payload split to MU */
        uint32_t sop; /* start of packet offset */
        sop = PIF_PKT_SOP(pif_pkt_info_global.pkt_buf, pif_pkt_info_global.pkt_num);
        mu_len = pif_pkt_info_global.pkt_len - (256 << pif_pkt_info_global.ctm_size) + sop;
    } else /* no data in MU */
        mu_len = 0;

    /* debug info for mu_split */
    pif_mu_len = mu_len;

    /* get the ctm byte count:
     * packet length - offset to parsed headers - byte_count_in_mu
     * Note: the parsed headers are always in ctm
     */
    count = pif_pkt_info_global.pkt_len - pif_pkt_info_global.pkt_pl_off - mu_len;
    /* Get a pointer to the ctm portion */
    payload = pif_pkt_info_global.pkt_buf;
    /* point to just beyond the parsed headers */
    payload += pif_pkt_info_global.pkt_pl_off;

    while (count) {
        /* grab a maximum of chunk */
        to_read = count > CHUNK_B ? CHUNK_B : count;

        /* grab a chunk of memory into transfer registers */
        mem_read8(&pl_data, payload, to_read);

        /* copy from transfer registers into local memory
         * we can iterate over local memory, where transfer
         * registers we cant
         */
        for (i = 0; i < CHUNK_LW; i++)
            pl_mem[i] = pl_data[i];

        /* iterate over all the bytes and do the search */
        for (i = 0; i < to_read; i++) {
            uint8_t val = pl_mem[i/4] >> (8 * (3 - (i % 4)));

            if (val == search_string[search_progress])
                search_progress += 1;
            else
                search_progress = 0;

            if (search_progress >= sizeof(search_string)) {
                mem_incr32((__mem uint32_t *)&search_detections);
                mem_incr32((__mem uint32_t *)&search_ctm_detections);

                /* drop if found */
                //return PIF_PLUGIN_RETURN_DROP;
            }
        }

        payload += to_read;
        count -= to_read;
    }

    /* same as above, but for mu. Code duplicated as a manual unroll */
    if (mu_len) {
        payload = (__addr40 void *)((uint64_t)pif_pkt_info_global.muptr << 11);
        /* Adjust payload size depending on the ctm size for the packet */
        payload += 256 << pif_pkt_info_global.ctm_size;        
        count = mu_len;
        while (count) {
            /* grab a maximum of chunk */
            to_read = count > CHUNK_B ? CHUNK_B : count;

            /* grab a chunk of memory into transfer registers */
            mem_read8(&pl_data, payload, to_read);

            /* copy from transfer registers into local memory
             * we can iterate over local memory, where transfer
             * registers we cant
             */
            for (i = 0; i < CHUNK_LW; i++)
                pl_mem[i] = pl_data[i];

            /* iterate over all the bytes and do the search */
            for (i = 0; i < to_read; i++) {
                uint8_t val = pl_mem[i/4] >> (8 * (3 - (i % 4)));

                if (val == search_string[search_progress])
                    search_progress += 1;
                else
                    search_progress = 0;

                if (search_progress >= sizeof(search_string)) {
                    mem_incr32((__mem uint32_t *)&search_detections);
                    mem_incr32((__mem uint32_t *)&search_mu_detections);

                    /* drop if found */
                    //return PIF_PLUGIN_RETURN_DROP;
                }
            }

            payload += to_read;
            count -= to_read;
        }
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}
