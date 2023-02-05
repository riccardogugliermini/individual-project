/* 
* Riccardo Gugliermini (riccardo.gugliermini@kcl.ac.uk)
* 20059776
*/

// P4_16
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROTOCOL_TCP = 0x6;
const bit<8>  IP_PROTOCOL_ICMP = 0x01;


// HEADERS
typedef bit<9>  egressSpec_t;
typedef bit<9>  ingressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Ethernet Header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// IPv4 Header
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

// TCP Header
header tcp_t {
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<32>   seqNo;
    bit<32>   ackNo;
    bit<4>    dataOffset;
    bit<6>    res;
    bit<6>    flags;
    bit<16>   window;
    bit<16>   checksum;
    bit<16>   urgentPtr;
}

// ICMP header
header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> seqNo;
    bit<32> data;
}

struct metadata {
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}

register <bit<32>>(1024) blacklist_register;
register <bit<32>>(1024) syn_open_register;
register <bit<32>>(1024) victimIp_register;
register <bit<32>>(1024) victimPort_register;

// ---- PARSER ----
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
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
            IP_PROTOCOL_ICMP: parse_icmp;
            IP_PROTOCOL_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// ---- CHECKSUM VERIFICATION ----
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


// ---- INGRESS PROCESSING ----
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    // ACTIONS
    action drop() {
        mark_to_drop(standard_metadata);
    }

     action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action count_synConnection(){
        // Diagnostics
        meta.routerPort = 4;
        log_msg("count_synConnection: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_synConnection: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_synConnection: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_sipBye: meta.routerPort = {}", {meta.routerPort});

        // Not a known attacker. Count the invite
        meta.synopencounter1 = meta.synopencounter1 + 1;
        meta.synopencounter2 = meta.synopencounter2 + 1;
        syn_open_register.write((bit<32>)meta.hashindex1, meta.synopencounter1);
        syn_open_register.write((bit<32>)meta.hashindex2, meta.synopencounter2);

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

    table blacklist {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }

        actions = {
            drop;
        }
        default_action = NoAction();
    }

     table SYN_count_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
        }
        actions = {
            count_synConnection;
            drop;
            NoAction;
        }
        size = 1024;
        // default_action = drop();
        const default_action = NoAction();
    }

    apply {

         if (hdr.ipv4.isValid()) {

            //KnownVictim_table.apply();

            ipv4_lpm.apply();

            if (hdr.tcp.isValid()) {

                if (hdr.tcp.flags[4]) {
                    log_msg("TCP request = SYN");

                    // Generate meta.hashindex1 for bloom filter index
                    hash(  meta.hashindex1, 
                            HashAlgorithm.crc32, 
                            10w0, 
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.dstPort},
                            10w1023
                    );
                    // Generate meta.hashindex2 for bloom filter index
                    hash(  meta.hashindex2,
                            HashAlgorithm.crc16,
                            10w0,
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.dstPort},
                            10w1023
                    );

                    // Is this a known attacker?
                    syn_open_register.read(meta.synopencounter1, (bit<32>)meta.hashindex1);
                    syn_open_register.read(meta.synopencounter2, (bit<32>)meta.hashindex2);
                    log_msg("INGRESS.Apply meta.synopencounter1 = {}", {meta.synopencounter1});
                    log_msg("INGRESS.Apply meta.synopencounter2 = {}", {meta.synopencounter2});
                    log_msg("INGRESS.Apply meta.portLimit = {}", {meta.portLimit});
                    if ((meta.synopencounter1 > meta.portLimit) && (meta.synopencounter2 > meta.portLimit)){
                        log_msg("The attacker is: {}", {hdr.ipv4.srcAddr});
                        log_msg("The targeted DoS IP: {}", {hdr.ipv4.dstAddr});
                        log_msg("The targeted DoS UDP: {}", {hdr.tcp.dstPort});
                        victimIp_register.write((bit<32>)meta.hashindex1, hdr.ipv4.dstAddr);
                        victimPort_register.write((bit<32>)meta.hashindex1, (bit<32>)hdr.tcp.dstPort);
                        drop();
                    } 

                    SYN_count_table.apply();
                }
            }
        }
    }

}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {}
}

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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.sip);
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
