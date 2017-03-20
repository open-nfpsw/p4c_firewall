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


header_type meta_t {
    fields {
        tcpLength : 16;
    }
}

metadata meta_t meta;

header_type nat_meta_t {
    fields {
        nat_ip : 32;
        nat_port : 16;
    }
}

metadata nat_meta_t nat_meta;