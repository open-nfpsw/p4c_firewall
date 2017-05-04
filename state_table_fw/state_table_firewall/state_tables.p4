header_type state_meta_t {
    fields {    
        state : 32;                             // state
        ip : 32;                                // ip used for NAT
        port : 16;                              // port used for NAT
        hit_count : 32;                         // number of hits since connection was made

        nat_ip : 32;                            // private ip kept for hashfunction in update_state
        nat_port : 16;                          // private port kept for hashfunction in update_state
    }
}

metadata state_meta_t state_meta;


primitive_action lookup_state();

action lookup_state_table() {
    lookup_state();
}


primitive_action state_update();

action update_state_table() {
    state_update();
}

table state_lookup {
    actions {
        lookup_state_table;
    }
}
