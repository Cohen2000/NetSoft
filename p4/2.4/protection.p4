/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_PROT = 0xFD; // Tunnel protocol identifier

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> seqNo_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Protection header
header prot_t {
    bit<8>  nextProto;
    seqNo_t seqNo;
}

struct metadata {
    bit<32> node_id;
    bit<1>  should_clone;  // Flag für Cloning
    bit<1>  prot_handled; 
    bit<32> clone_session; // Clone session ID
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       outer_ipv4;    // Tunnel header
    prot_t       prot;          // Protection header
    ipv4_t       inner_ipv4;    // Original packet
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_outer_ipv4;
            default: accept;
        }
    }

    state parse_outer_ipv4 {
        packet.extract(hdr.outer_ipv4);
        transition select(hdr.outer_ipv4.protocol) {
            PROTO_PROT: parse_prot;
            default: accept;
        }
    }

    state parse_prot {
        packet.extract(hdr.prot);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Registers for sequence management per tunnel direction
    register<seqNo_t>(2) next_seq;      
    register<seqNo_t>(2) expected_seq;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // Normal IPv4 forwarding
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.outer_ipv4.ttl = hdr.outer_ipv4.ttl - 1;
    }

    // Add protection header and IPv4 tunnel
    action add_protection_tunnel_and_clone(macAddr_t dstAddr, ip4Addr_t tunnel_dst, ip4Addr_t tunnel_src, 
                               egressSpec_t port, bit<32> register_idx, bit<32> mirror_session_id) {
        // Get sequence number
        seqNo_t cur_seq;
        next_seq.read(cur_seq, register_idx);
        next_seq.write(register_idx, cur_seq + 1);

        // Move original IPv4 to inner
        hdr.inner_ipv4 = hdr.outer_ipv4;
        hdr.inner_ipv4.setValid();
        
        // Create protection header
        hdr.prot.setValid();
        hdr.prot.nextProto = 0x04; // IPv4
        hdr.prot.seqNo = cur_seq;

        // Create outer IPv4 tunnel header
        hdr.outer_ipv4.version = 4;
        hdr.outer_ipv4.ihl = 5;
        hdr.outer_ipv4.diffserv = 0;
        hdr.outer_ipv4.totalLen = hdr.inner_ipv4.totalLen + 20 +5; 
        hdr.outer_ipv4.identification = 0;
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.fragOffset = 0;
        hdr.outer_ipv4.ttl = 64;
        hdr.outer_ipv4.protocol = PROTO_PROT;
        hdr.outer_ipv4.srcAddr = tunnel_src;
        hdr.outer_ipv4.dstAddr = tunnel_dst;
        hdr.outer_ipv4.hdrChecksum = 0;
        hdr.outer_ipv4.setValid();

        // Set output port
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr; 

        meta.should_clone = 1;
        meta.clone_session = mirror_session_id;
    }

    // Remove protection tunnel and forward inner packet
    action remove_protection_tunnel(macAddr_t dstAddr, egressSpec_t port) {
        // Move inner IPv4 back to outer
        hdr.outer_ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.prot.setInvalid();

        // Forward packet
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.outer_ipv4.ttl = hdr.outer_ipv4.ttl - 1;
    }

    action set_node_id(bit<32> id) {
        meta.node_id = id;
    }
    
    // Normal IPv4 forwarding table
    table ipv4_lpm {
        key = {
            hdr.outer_ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // Protection encapsulation table
    table protection_encap {
        key = {
            hdr.outer_ipv4.dstAddr: lpm;
        }
        actions = {
            add_protection_tunnel_and_clone;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    // Protection decapsulation table
    table protection_decap {
        key = {
            hdr.outer_ipv4.dstAddr: lpm;
        }
        actions = {
            remove_protection_tunnel;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    table identify_node {
        actions = {
            set_node_id;
            NoAction;
        }
        size = 1;
    }

    apply {
        identify_node.apply();

        if (!hdr.outer_ipv4.isValid()) return;
        
        // reset flag
        meta.prot_handled = 0;
        
        if (hdr.prot.isValid()){
            if (meta.node_id == 1 || meta.node_id == 3) { // tunnel endpoints
                // This is a tunneled protection packet - check sequence and decapsulate
                bit<32> reg_idx = 0;
                // Determine register index based on tunnel destination
                if (hdr.outer_ipv4.dstAddr == 0x0A010001) { // 10.1.0.1 (S1)
                    reg_idx = 0;
                } else if (hdr.outer_ipv4.dstAddr == 0x0A030003) { // 10.3.0.3 (S3)
                    reg_idx = 1;
                }
                
                seqNo_t expected;
                expected_seq.read(expected, reg_idx);
                
                if (hdr.prot.seqNo == expected) {
                    // Accept packet and update expected sequence
                    expected_seq.write(reg_idx, expected + 1);
                    protection_decap.apply();
                    meta.prot_handled = 1;
                    
                } else {
                    // Drop duplicate
                    drop();
                    return;
                }
            }
        }

        if (!hdr.prot.isValid() && (meta.node_id == 1 || meta.node_id == 3)) {
            if (protection_encap.apply().hit) {
                meta.prot_handled = 1;
            }
        }

        if (meta.prot_handled == 0) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  
        if (meta.should_clone == 1){
            clone(CloneType.E2E, meta.clone_session);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.outer_ipv4.isValid(),
            { hdr.outer_ipv4.version,
              hdr.outer_ipv4.ihl,
              hdr.outer_ipv4.diffserv,
              hdr.outer_ipv4.totalLen,
              hdr.outer_ipv4.identification,
              hdr.outer_ipv4.flags,
              hdr.outer_ipv4.fragOffset,
              hdr.outer_ipv4.ttl,
              hdr.outer_ipv4.protocol,
              hdr.outer_ipv4.srcAddr,
              hdr.outer_ipv4.dstAddr },
            hdr.outer_ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.prot);
        packet.emit(hdr.inner_ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;