#include "parser.p4"
#include "headers.p4"
#include "intrinsic.p4"
#include "checksum.p4"

#define ETHERTYPE_ARP 0x0806

primitive_action lookup_state();


action nat_int_ext(port) {
    modify_field(state_meta.incoming_port,0);
    lookup_state();
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.srcAddr,state_meta.ip);
    modify_field(tcp.srcPort,state_meta.port);
}

action nat_ext_int(port) {
    modify_field(state_meta.incoming_port,1);
    lookup_state();
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.dstAddr,state_meta.ip);
    modify_field(tcp.dstPort,state_meta.port);
}


table nat {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        nat_int_ext;
        nat_ext_int;
    }
}


primitive_action clear_public_ports();

action clear_ports() {
    clear_public_ports();
}

table controller_pkt {
    reads {
        standard_metadata.ingress_port: exact;
    }
    actions {
        clear_ports;
    }
}


control ingress {
    if (ethernet.etherType == ETHERTYPE_CUSTOM)
        apply(controller_pkt);
    apply(nat);
}

control egress {

}
