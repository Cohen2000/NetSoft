/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
register<bit<1>>(1) lag_state;
const bit<9> PORT_LINK_1 = 2;
const bit<9> PORT_LINK_2 = 3;
const bit<9> LAG_PORT = 99;
const bit<32> HASH_BASE = 0;
const bit<32> HASH_MOD  = 2;

counter(2, CounterType.packets_and_bytes) lag_counter_packet_based;
counter(2, CounterType.packets_and_bytes) lag_counter_flow_based;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header_union transport_t {
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    transport_t  transport;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.transport.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.transport.udp);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action read_and_flip(out bit<1> state) {
        lag_state.read(state, 0);
        bit<1> new_state = state ^ 1w1;
        lag_state.write(0, new_state);
    }

    // no ports and MACs needed as parameters! We just use the ports internally specified by the topology 
    action lag_packet_based(){
        
        bit<1> actual_state;
        bit<32> counter_index = 0;

        read_and_flip(actual_state);

        // send the packet over one of the links depending on the state
        if (actual_state == 0) {
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            standard_metadata.egress_spec = PORT_LINK_1;
            counter_index = 0;
        } else {
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            standard_metadata.egress_spec = PORT_LINK_2;
            counter_index = 1;
        }

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        lag_counter_packet_based.count(counter_index);
    }


    action lag_flow_based_tcp() {
        bit<32> h;
        bit<32> counter_index = 0;

        // IP + TCP-Ports
        hash(h, HashAlgorithm.crc32, HASH_BASE, {
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol,
            hdr.transport.tcp.srcPort,
            hdr.transport.tcp.dstPort
        }, HASH_MOD);

        if (h == 0) {
            standard_metadata.egress_spec = PORT_LINK_1;
            counter_index = 0;
        } else {
            standard_metadata.egress_spec = PORT_LINK_2;
            counter_index = 1;
        }

        lag_counter_flow_based.count(counter_index);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action lag_flow_based_udp() {
        bit<32> h;
        bit<32> counter_index = 0;

        // IP + UDP-Ports
        hash(h, HashAlgorithm.crc32, HASH_BASE, {
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol,
            hdr.transport.udp.srcPort,
            hdr.transport.udp.dstPort
        }, HASH_MOD);
        
        if (h == 0) {
            standard_metadata.egress_spec = PORT_LINK_1;
            counter_index = 0;
        } else {
            standard_metadata.egress_spec = PORT_LINK_2;
            counter_index = 1;
        }

        lag_counter_flow_based.count(counter_index);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table lag_flow_and_packet_based {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            lag_packet_based;
            lag_flow_based_tcp;
            lag_flow_based_udp;
        }
        size = 1024;
        default_action = lag_packet_based();
    }

   
    apply {
        if (hdr.ipv4.isValid()) {
       		ipv4_lpm.apply();
            if (standard_metadata.egress_spec == LAG_PORT) {
                lag_flow_and_packet_based.apply();
            }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.transport);
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
