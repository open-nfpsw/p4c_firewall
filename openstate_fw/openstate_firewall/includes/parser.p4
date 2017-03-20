#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_CUSTOM 0x6161
#define UDP_PROTOCOL 0x11
#define TCP_PROTOCOL 0x06

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_CUSTOM : parse_controller_pkt;
        ETHERTYPE_ARP: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(meta.tcpLength, ipv4.totalLen - 20);
    return select(ipv4.protocol) {
        TCP_PROTOCOL : parse_tcp;
        UDP_PROTOCOL : parse_udp;
        default : ingress;
    }
}


parser parse_controller_pkt {
    extract(clr_prts_hdr);
    return ingress;
}

parser parse_udp {
    extract(udp);
    return  ingress;
}


parser parse_tcp {
    extract(tcp);
    return  ingress;
}
