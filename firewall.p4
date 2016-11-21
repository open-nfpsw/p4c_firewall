#include "includes/headers.p4"
#include "includes/parser.p4"




//Counter
counter nat_pkts_counter {
    type : packets; //bytes
    direct : nat;
}
// /Counter



//Checksum

//IPv4 Checksum
field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    16'0;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}
// /IPv4 Checksum


//TCP Checksum
field_list tcp_ipv4_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    meta.tcpLength;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.ecn;
    tcp.ctrl;
    tcp.window;
    tcp.urgentPtr;
    payload;
}

field_list_calculation tcp_ipv4_checksum {
    input {
        tcp_ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum  {
    verify tcp_ipv4_checksum if (valid(ipv4));
    update tcp_ipv4_checksum if (valid(ipv4));
}
// /TCP Checksum


// /Checksum





//NAT
//nat and send out external port
action nat_int_ext_hit(port, srcAddr, srcPort) {
    modify_field(standard_metadata.egress_spec, port);

    modify_field(ipv4.srcAddr,srcAddr);
    modify_field(tcp.srcPort,srcPort);
}

//nat and allow in - send to port that original/outgoing request came from
action nat_ext_int_hit(port, dstAddr, dstPort) {
    modify_field(standard_metadata.egress_spec, port);
    
    modify_field(ipv4.dstAddr,dstAddr);
    modify_field(tcp.dstPort,dstPort);
}

//update rule - port number is controller port
action nat_int_ext_miss(port) {
    modify_field(standard_metadata.egress_spec, port);
    
}

//drop
action nat_ext_int_miss() {
    drop();
}


table nat {
    reads {
        standard_metadata.ingress_port : exact; 
        ipv4 : valid;
        tcp : valid;
        ipv4.srcAddr : ternary;
        ipv4.dstAddr : ternary;
        tcp.srcPort : ternary;
        tcp.dstPort : ternary;
    }
    actions {
        nat_int_ext_hit;
        nat_ext_int_hit;
        nat_int_ext_miss;
        nat_ext_int_miss; //make default
    }
}

// /NAT




// From Controller: Remove Header

//We know which port the controller is on
action do_remove_header() {
    remove_header(controller_header);
 //   modify_field(standard_metadata.egress_spec,port);
}

table from_controller {
    reads {
        standard_metadata.ingress_port : exact;  //controller port number
    }
    actions { 
        do_remove_header; 
    }
    size : 1; // will there always only be one controller? size : 1;?
}
// /From Controller: Remove Header






//Ingress Control

control ingress {
  apply(from_controller);
  apply(nat);
  
}

// /Ingress Control




// Egress Tables + Actions


//Controller Add Header

action do_add_header() {
    add_header(controller_header);
    modify_field(controller_header.reason, 1); // Reason 1 is because nat int_ext_miss
    modify_field(controller_header.fromPort, standard_metadata.ingress_port); //to remember which port to return request to
}



table to_controller {
    reads {
        standard_metadata.egress_port : exact;  //controller port number
    }
    actions { 
        do_add_header; 
    }
    size : 1; // will there always only be one controller? size : 1;?
}

// /Controller Add Header


//Scan Payload

primitive_action payload_scan();

action scan_payload() {
    payload_scan();
}


table payloadscan {
    reads {
        standard_metadata.ingress_port : exact;  //port number - internal and external should be scanned  
    }
    actions { 
        scan_payload; 
    }
}

// /Scan Payload



// Egress Control

control egress {
    apply(to_controller);
    apply(payloadscan);
}

// /Egress Control