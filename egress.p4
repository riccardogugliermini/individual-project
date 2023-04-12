/*
* Riccardo Gugliermini (riccardo.gugliermini@kcl.ac.uk)
* 20059776
*/

// P4_16
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROTOCOL_TCP = 0x6;


// HEADERS
typedef bit<9>  egressSpec_t;
typedef bit<9>  ingressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<6>  tcp_headers_t;

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
    bit<1>    urg;
    bit<1>    ack;
    bit<1>    psh;
    bit<1>    rst;
    bit<1>    syn;
    bit<1>    fin;
    bit<16>   window;
    bit<16>   checksum;
    bit<16>   urgentPtr;
}


struct metadata {
    bit<32>    syncounter1;
    bit<32>    syncounter2;

    bit<10>    icmphashindex1;
    bit<10>    icmphashindex2;

    bit<32>    srcAddr;

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

// SYN Flood Egress Bloom Filter - Open Connections Counter
register <bit<32>>(1024) egress_syn_register;

// THRESHOLDS
const bit<32> EGRESS_SYN_TRESHOLD = 10;

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
            IP_PROTOCOL_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/* ------ CHECKSUM VERIFICATION ------ */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}


/* ------ INGRESS PROCESSING ------ */
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
      standard_metadata.egress_spec = port;
      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
      hdr.ethernet.dstAddr = dstAddr;
      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
      key = {
          hdr.ipv4.dstAddr: lpm;
      }
      actions = {
          ipv4_forward;
          NoAction;
      }
      size = 1024;
      default_action = NoAction();
    }

    apply {

       if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
       }
    }

}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

     action drop() {
        mark_to_drop(standard_metadata);
    }

    action egress_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action egress_count_tcpSyn() {
        meta.syncounter1 = meta.syncounter1 + 1;
        meta.syncounter2 = meta.syncounter2 + 1;

        egress_syn_register.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        egress_syn_register.write((bit<32>)meta.synhashindex2, meta.syncounter2);
    }

    action egress_decrease_tcpSyn() {
        if (meta.syncounter1 > 0 && meta.syncounter2 > 0) {
            meta.syncounter1 = meta.syncounter1 - 1;
            meta.syncounter2 = meta.syncounter2 - 1;
        }

        egress_syn_register.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        egress_syn_register.write((bit<32>)meta.synhashindex2, meta.syncounter2);
    }

    table egress_ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            egress_ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table egress_SYN_count_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            egress_count_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = egress_count_tcpSyn();
    }


    table egress_SYN_decrease_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            egress_decrease_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = egress_decrease_tcpSyn();
    }


     apply {
        if (hdr.ipv4.isValid()) {

            egress_ipv4_lpm.apply();

            if (hdr.tcp.isValid()) {

                // Generate meta.synhashindex1 for bloom filter index
                hash(  meta.synhashindex1,
                        HashAlgorithm.crc32,
                        10w0,
                        {hdr.ipv4.dstAddr},
                        10w1023
                );
                // Generate meta.synhashindex2 for bloom filter index
                hash(  meta.synhashindex2,
                        HashAlgorithm.crc16,
                        10w0,
                        {hdr.ipv4.dstAddr},
                        10w1023
                );

                // ACK
                if (hdr.tcp.ack == 1) {
                    egress_SYN_decrease_table.apply();
                    log_msg("TCP ACK");
                }

                //SYN request
                if (hdr.tcp.syn == 1) {
                    log_msg("TCP request = SYN");


                    egress_syn_register.read(meta.syncounter1, (bit<32>)meta.synhashindex1);
                    egress_syn_register.read(meta.syncounter2, (bit<32>)meta.synhashindex2);

                    if ((meta.syncounter1 > EGRESS_SYN_TRESHOLD) && (meta.syncounter2 > EGRESS_SYN_TRESHOLD)){
                        drop();
                    }

                    egress_SYN_count_table.apply();
                }
            }
        }
    }
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
        packet.emit(hdr.tcp);
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
