header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset :4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}


header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
    }
}

header_type icmp_t {
    fields {
        icmp_type : 8;
        icmp_code : 8;
        icmp_csum : 16;
    }
}
/*
header_type clr_prts_hdr_t {
    fields {
        public_ip : 32;
        number_of_ports : 16;
        port_numbers : *;
    }
    length : number_of_ports + 0;
    max_length : 40;
}
*/

header_type clr_prts_hdr_t {
    fields {
        ports_hdr_field : 32;
    }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
header tcp_t tcp;
header clr_prts_hdr_t clr_prts_hdr;
header icmp_t icmp;

header_type meta_t {
    fields {
        tcpLength : 16;
    }
}

metadata meta_t meta;

header_type state_meta_t {
    fields {    
        state : 32;                             // state
        ip : 32;                                // ip used for NAT
        port : 16;                              // port used for NAT
        hit_count : 32;                         // number of hits since connection was made

///        nat_ip : 32;                            // private ip kept for hashfunction in update_state
//        nat_port : 16;                          // private port kept for hashfunction in update_state

        incoming_port : 1;                      //Trusted = 0, Untrusted = 1
    }
}

metadata state_meta_t state_meta;

