#include "parser.p4"
#include "headers.p4"
#include "intrinsic.p4"

#include "state_tables.p4"
#include "checksum.p4"

#define ETHERTYPE_ARP 0x0806


action nat_int_ext_hit(port) {
    modify_field(standard_metadata.egress_spec, port);

    modify_field(ipv4.srcAddr,state_meta.ip);
    modify_field(tcp.srcPort,state_meta.port);
}

action nat_ext_int_hit(port) {
    modify_field(standard_metadata.egress_spec, port);

    modify_field(ipv4.dstAddr,state_meta.ip);
    modify_field(tcp.dstPort,state_meta.port);
}

primitive_action get_public_port();

action nat_int_ext_miss(port) {
    modify_field(standard_metadata.egress_spec, port);

    get_public_port();

}

action nat_ext_int_miss() {
    drop();
}


table nat {
    reads {
        standard_metadata.ingress_port : exact;
        state_meta.state : exact;
//        ipv4.dstAddr : ternary;
//        ipv4.srcAddr : ternary;
//        ipv4.dstAddr : lpm;
    }
    actions {
        nat_int_ext_hit;
        nat_ext_int_hit;
        nat_int_ext_miss;
        nat_ext_int_miss;
    }
}


table update_state {
    reads{
        standard_metadata.ingress_port : exact;
        state_meta.state : exact;
    }
    actions {
        update_state_table;
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

action do_forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward {
    reads {
        standard_metadata.ingress_port: exact;
    }
    actions {
        do_forward;
    }

}


control ingress {
// ARP and ICMP added for iperf tests
//    if ((ethernet.etherType == ETHERTYPE_ARP) or (ipv4.protocol == 1)) {
//        apply(forward);
//    } else {
        apply(controller_pkt);
        apply(state_lookup);
        apply(nat);
        apply(update_state);
//    }
}

control egress {

}
