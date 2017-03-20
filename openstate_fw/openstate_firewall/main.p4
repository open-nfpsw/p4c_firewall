#include "includes/parser.p4"
#include "includes/headers.p4"
#include "includes/intrinsic.p4"

//#define STATE_MAP_SIZE 13    // 13 bits = 8192 state entries
//#define STATE_TABLE_SIZE 8192
//#define STATE_MAP_SIZE 16    // 16 bits = 65536 state entries
//#define STATE_TABLE_SIZE 65536
#define STATE_MAP_SIZE 20    // 20 bits = 0xFFFFF state entries
#define STATE_TABLE_SIZE 0xFFFFF
//#define STATE_MAP_SIZE 32    // 32 bits = 0xFFFFFFFF state entries
//#define STATE_TABLE_SIZE 0xFFFFFFFF
#include "openstate.p4"
#include "checksum.p4"


field_list lookup_hash_field {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
}

field_list update_hash_field {
    nat_meta.nat_ip; //private_ip
    ipv4.dstAddr;
    nat_meta.nat_port; //private_port
    tcp.dstPort;
}

field_list update_hash_field_for_response {
    ipv4.dstAddr;
    ipv4.srcAddr; // public_ip
    tcp.dstPort;
    tcp.srcPort;  // public_port
}

action nat_int_ext_hit(port) {
    modify_field(standard_metadata.egress_spec, port);

    register_read(ipv4.srcAddr,reg_public_ip, openstate.lookup_state_index);
    register_read(tcp.srcPort,reg_public_port, openstate.lookup_state_index);

    //For timeout:
    add_to_field(openstate.hit_count, 1);
    register_write(reg_hit_count, openstate.lookup_state_index, openstate.hit_count);
}

action nat_ext_int_hit(port) {
    modify_field(standard_metadata.egress_spec, port);

    register_read(ipv4.dstAddr,reg_private_ip, openstate.lookup_state_index);
    register_read(tcp.dstPort,reg_private_port, openstate.lookup_state_index);

    //For timeout:
    add_to_field(openstate.hit_count, 1);
    register_write(reg_hit_count, openstate.lookup_state_index, openstate.hit_count);
}

primitive_action get_public_port();

action nat_int_ext_miss(port) {
    modify_field(standard_metadata.egress_spec, port);

    get_public_port();

    //For timeout:
    //register_write(reg_hit_count, openstate.lookup_state_index, 1);
    //Moved to updatestate
    //register_write(reg_hit_count, openstate.update_state_index, 1);
    //register_write(reg_hit_count, openstate.update_state_index_response, 1);

}

action nat_ext_int_miss() {
    drop();
}


table nat {
    reads {
        standard_metadata.ingress_port : exact;
        openstate.state : exact;
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
        openstate.state : exact;
    }
    actions {
        update_state_table;
//        update_state_table_to;
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
    apply(controller_pkt);
    apply(state_lookup);

    //check if the idle timeout is set.and current packet timestamp is greater than the timeout expiration time
//    if ((openstate.idle_to > 0) and (intrinsic_metadata.ingress_global_timestamp >= openstate.idle_to_expiration) and (openstate.idle_to_expiration > 0))
//    {
//        apply(idle_to_expired);
//    }
    apply(nat);
    apply(update_state);
}

control egress {
    
}

