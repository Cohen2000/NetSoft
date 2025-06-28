/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4    = 0x0800;
const bit<16> TYPE_IPV6    = 0x86dd;
const bit<8>  PROTO_6IN4   = 41;

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;

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

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

struct metadata {
    bit<1> is_6in4;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
}

/*************************************************************************
 *                                PARSER                                *
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta) {
    state start {
        meta.is_6in4 = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_6IN4: parse_inner_ipv6;
            default:    accept;
        }
    }

    state parse_inner_ipv6 {
        packet.extract(hdr.ipv6);
        meta.is_6in4 = 1;
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition accept;
    }
}

/*************************************************************************
 *                           VERIFY CHECKSUM                            *
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 *                         INGRESS PROCESSING                           *
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t stdmeta) {

    action drop() {
        mark_to_drop(stdmeta);
    }

    action ipv4_forward(macAddr_t dstMac, egressSpec_t port) {
        stdmeta.egress_spec    = port;
        hdr.ethernet.srcAddr   = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr   = dstMac;
        hdr.ipv4.ttl           = hdr.ipv4.ttl - 1;
    }

    action ipv6_forward(macAddr_t dstMac, egressSpec_t port) {
        stdmeta.egress_spec    = port;
        hdr.ethernet.srcAddr   = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr   = dstMac;
        hdr.ipv6.hopLimit      = hdr.ipv6.hopLimit - 1;
    }

    action encapsulate_6in4(ip4Addr_t src4, ip4Addr_t dst4,
                            macAddr_t  nextHopMac, egressSpec_t port) {
        // Neuer IPv4‐Header
        hdr.ipv4.setValid();
        hdr.ipv4.version     = 4;
        hdr.ipv4.ihl         = 5;
        hdr.ipv4.diffserv    = 0;
        hdr.ipv4.totalLen    = hdr.ipv6.payloadLen + 40 + 20;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags       = 2;
        hdr.ipv4.fragOffset  = 0;
        hdr.ipv4.ttl         = 64;
        hdr.ipv4.protocol    = PROTO_6IN4;
        hdr.ipv4.hdrChecksum = 0;
        hdr.ipv4.srcAddr     = src4;
        hdr.ipv4.dstAddr     = dst4;

        // Ethernet
        hdr.ethernet.srcAddr   = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr   = nextHopMac;
        hdr.ethernet.etherType = TYPE_IPV4;

        stdmeta.egress_spec = port;
    }

    table ipv4_lpm {
        key        = { hdr.ipv4.dstAddr: lpm; }
        actions    = { ipv4_forward; drop; }
        size       = 1024;
        default_action = drop();
    }

    table ipv6_lpm {
        key        = { hdr.ipv6.dstAddr: lpm; }
        actions    = { ipv6_forward; encapsulate_6in4; drop; }
        size       = 1024;
        default_action = drop();
    }

    apply {
        if (meta.is_6in4 == 1) {
            // Decapsulate: außen IPv4 raus, dann normales IPv6‐Forwarding
            hdr.ipv4.setInvalid();
            hdr.ethernet.etherType = TYPE_IPV6;
            // HopLimit wird jetzt nur einmal in ipv6_forward dekrementiert
            ipv6_lpm.apply();
        } else if (hdr.ipv6.isValid()) {
            // normales IPv6 (oder 6in4‐Encap)
            ipv6_lpm.apply();
        } else if (hdr.ipv4.isValid()) {
            // normales IPv4
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

/*************************************************************************
 *                         EGRESS & CHECKSUM                            *
 *************************************************************************/
control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t stdmeta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
