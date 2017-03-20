header_type openstate_t {
    fields {
        lookup_state_index : STATE_MAP_SIZE; // state map index
        update_state_index : STATE_MAP_SIZE; // state map index
        update_state_index_response : STATE_MAP_SIZE; // state map index
        hit_count : 32;

        idle_to: 64;                         // idle timeout
        idle_to_expiration : 64;             // last reference time
        new_idle_to_expiration : 64;         // new reference time

        state : 32;                          // state
    }
}

metadata openstate_t openstate;

register reg_state {
    width : 32;
    instance_count : STATE_TABLE_SIZE;
}

register reg_idle_to {
    width : 64;
    instance_count : STATE_TABLE_SIZE;
}

register reg_idle_to_expiration {
    width : 64;
    instance_count : STATE_TABLE_SIZE;
}


register reg_public_ip {
    width : 32;
    instance_count : STATE_TABLE_SIZE;
}


register reg_public_port {
    width : 16;
    instance_count : STATE_TABLE_SIZE;
}


register reg_private_ip {
    width : 32;
    instance_count : STATE_TABLE_SIZE;
}


register reg_private_port {
    width : 16;
    instance_count : STATE_TABLE_SIZE;
}

register reg_hit_count {
    width : 32;
    instance_count : STATE_TABLE_SIZE;
}

field_list_calculation l_hash {
    input {
        lookup_hash_field;
    }
    algorithm : crc32;
    output_width : 32;
}

field_list_calculation u_hash {
    input {
        update_hash_field;
    }
    algorithm : crc32;
    output_width : 32;
}

field_list_calculation u_hash_response {
    input {
        update_hash_field_for_response;
    }
    algorithm : crc32;
    output_width : 32;
}

action lookup_state_table() {
    //store the new hash value used for the lookup
    modify_field_with_hash_based_offset(openstate.lookup_state_index, 0, l_hash, STATE_TABLE_SIZE);
    //Using the new hash, we perform the lookup reading the reg_state[idx]
    register_read(openstate.state,reg_state, openstate.lookup_state_index);

/*
    //Store the idle_to[idx] value in the metadata
    register_read(openstate.idle_to, reg_idle_to, openstate.lookup_state_index);
    //Store the last idle timeout expiration time in the metadata
    register_read(openstate.idle_to_expiration, reg_idle_to_expiration, openstate.lookup_state_index);
*/

    //read hit_count
    register_read(openstate.hit_count, reg_hit_count, openstate.lookup_state_index);

/*
    //Calculation of the new idle_to_expiration value
    modify_field(openstate.new_idle_to_expiration, intrinsic_metadata.ingress_global_timestamp);
    add_to_field(openstate.new_idle_to_expiration, openstate.idle_to);
    register_write(reg_idle_to_expiration, openstate.lookup_state_index, openstate.new_idle_to_expiration);
*/
}

action update_state_table(state) {
    //store the new hash value used for the update
    modify_field_with_hash_based_offset(openstate.update_state_index, 0, u_hash, STATE_TABLE_SIZE);
    modify_field_with_hash_based_offset(openstate.update_state_index_response, 0, u_hash_response, STATE_TABLE_SIZE);

    //modify_field(tempmeta.state,state);
    //Using the new hash, we perform the update of the register reg_state[idx]
    register_write(reg_state, openstate.update_state_index, state);
    //same as above for response
    register_write(reg_state, openstate.update_state_index_response, state);

    register_write(reg_private_ip, openstate.update_state_index_response, nat_meta.nat_ip);
    register_write(reg_private_port, openstate.update_state_index_response, nat_meta.nat_port);
    register_write(reg_public_ip, openstate.update_state_index, ipv4.srcAddr);
    register_write(reg_public_port, openstate.update_state_index, tcp.srcPort);



/*
    //Set timeout for both outgoing and incoming packets:
    //Store in the register the new idle timeout
    register_write(reg_idle_to, openstate.update_state_index, idle_to);
    register_write(reg_idle_to, openstate.update_state_index_response, idle_to);
    //The expiration time is the sum between the idle timeout and when the timeout is set up
    modify_field(openstate.new_idle_to_expiration, intrinsic_metadata.ingress_global_timestamp);
    add_to_field(openstate.new_idle_to_expiration, idle_to);
    register_write(reg_idle_to_expiration, openstate.update_state_index, openstate.new_idle_to_expiration);
    register_write(reg_idle_to_expiration, openstate.update_state_index_response, openstate.new_idle_to_expiration);
*/
    register_write(reg_hit_count, openstate.update_state_index, 1);
    register_write(reg_hit_count, openstate.update_state_index_response, 1);

}

/*
action update_state_table_to(idle_to) {
    //Fastlane - only update these:

    // modify_field_with_hash_based_offset(openstate.update_state_index, 0, u_hash, STATE_TABLE_SIZE);
    // modify_field_with_hash_based_offset(openstate.update_state_index_response, 0, u_hash_response, STATE_TABLE_SIZE);
    //
    // //Store in the register the new idle timeout
    // register_write(reg_idle_to, openstate.update_state_index, idle_to);
    // //The expiration time is the sum between the idle timeout and when the timeout is set up
    // modify_field(openstate.new_idle_to_expiration, intrinsic_metadata.ingress_global_timestamp);
    // add_to_field(openstate.new_idle_to_expiration, idle_to);
    // register_write(reg_idle_to_expiration, openstate.update_state_index, openstate.new_idle_to_expiration);

        //Only update timeout for current flow?
        //Store in the register the new idle timeout
        register_write(reg_idle_to, openstate.lookup_state_index, idle_to);
        //The expiration time is the sum between the idle timeout and when the timeout is set up
        modify_field(openstate.new_idle_to_expiration, intrinsic_metadata.ingress_global_timestamp);
        add_to_field(openstate.new_idle_to_expiration, idle_to);
        register_write(reg_idle_to_expiration, openstate.lookup_state_index, openstate.new_idle_to_expiration);
}

action set_idle_rb_state(state) {
    //After the timeout expiration, the state and all the registers are reset to 0
    modify_field(openstate.state, state);
    // modify_field_with_hash_based_offset(openstate.update_state_index, 0, u_hash, STATE_TABLE_SIZE);
    // modify_field_with_hash_based_offset(openstate.update_state_index_response, 0, u_hash_response, STATE_TABLE_SIZE);

    register_write(reg_state, openstate.lookup_state_index, state);
    register_write(reg_idle_to_expiration, openstate.lookup_state_index, 0);
    register_write(reg_idle_to, openstate.lookup_state_index, 0);
    // register_write(reg_idle_to_expiration, openstate.update_state_index_response, 0);
    // register_write(reg_idle_to, openstate.update_state_index_response, 0);

    //??
    //register_write(reg_hit_count, openstate.lookup_state_index, 0);


}
*/


action __nop() {
}

table state_lookup {
    actions {
        lookup_state_table;
        __nop;
    }
}


table state_update {
    actions {
        update_state_table;
        __nop;
    }
}


/*
table idle_to_expired {
    actions {
        set_idle_rb_state;
        __nop;
    }
}
*/