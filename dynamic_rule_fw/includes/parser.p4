
/*
  +-------------------------------------------
    Define parser
  +-------------------------------------------
*/


#define IPV4_TYPE 0x0800
#define UDP_PROTOCOL 0x11
#define TCP_PROTOCOL 0x06



parser start {
  return select(current(0, 48)) {
    0 : parse_controller_header;
        default: parse_eth;
  }
}

parser parse_controller_header {
    extract(controller_header);
    return parse_eth;
}

parser parse_eth {
    extract(eth);
    return select (eth.etherType) {
        IPV4_TYPE : parse_ipv4;
        default: ingress;
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


parser parse_udp {
    extract(udp);
    return  ingress;
}


parser parse_tcp {
    extract(tcp);
    return  ingress;
}

