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
    // Syn counter - Open Connections
    bit<32>    syncounter1;
    bit<32>    syncounter2;
    bit<32>    syncounter3;
    bit<32>    syncounter4;

    // ICMP Counters
    bit<32>    icmpcounter1;
    bit<32>    icmpcounter2;
    bit<32>    icmpcounter3;
    bit<32>    icmpcounter4;

    // ICMP Update Timestamps
    bit<48>    icmptimestamp1;
    bit<48>    icmptimestamp2;
    bit<48>    icmptimestamp3;
    bit<48>    icmptimestamp4;

    // SYN Bloom Filters Indexes
    bit<16>    synhashindex1;
    bit<16>    synhashindex2;
    bit<16>    synhashindex3;
    bit<16>    synhashindex4;
    
    // ICMP Bloom Filters Indexes
    bit<10>    icmphashindex1;
    bit<10>    icmphashindex2;
    bit<10>    icmphashindex3;
    bit<10>    icmphashindex4;

    // IP Source Address
    bit<32>    srcAddr;

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}


// SYN Flood Ingress Bloom Filter - Open Connections Counter
register <bit<32>>(65536) ingress_syn_register1;
register <bit<32>>(65536) ingress_syn_register2;
register <bit<32>>(65536) ingress_syn_register3;
register <bit<32>>(65536) ingress_syn_register4;

// ICMP Flood Ingress Bloom Filter - ICMP Packets Counter
register <bit<32>>(65536) ingress_icmp_register1;
register <bit<32>>(65536) ingress_icmp_register2;
register <bit<32>>(65536) ingress_icmp_register3;
register <bit<32>>(65536) ingress_icmp_register4;

// ICMP Flood Timestamp Register
register <bit<48>>(65536) ingress_timestamp_register1;
register <bit<48>>(65536) ingress_timestamp_register2;
register <bit<48>>(65536) ingress_timestamp_register3;
register <bit<48>>(65536) ingress_timestamp_register4;

// THRESHOLDS
const bit<32> TCP_SYN_DROP_TRESHOLD = 4;
const bit<32> TCP_SYN_RESET_TRESHOLD = 14;

const bit<48> ICMP_TIMESTAMP_TRESHOLD = 5000000;    //50 seconds
const bit<32> ICMP_DROP_THRESHOLD = 20;
const bit<32> ICMP_RESET_THRESHOLD = 40;


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

/* ------ CHECKSUM VERIFICATION ------ */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/* ------ INGRESS PROCESSING ------ */
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    /* ---- COUNT TCP SYN ---- */
    action count_tcpSyn() {
        meta.syncounter1 = meta.syncounter1 + 1;
        meta.syncounter2 = meta.syncounter2 + 1;
        meta.syncounter3 = meta.syncounter3 + 1;
        meta.syncounter4 = meta.syncounter4 + 1;

        ingress_syn_register1.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        ingress_syn_register2.write((bit<32>)meta.synhashindex2, meta.syncounter2);
        ingress_syn_register3.write((bit<32>)meta.synhashindex3, meta.syncounter3);
        ingress_syn_register4.write((bit<32>)meta.synhashindex4, meta.syncounter4);

        log_msg("count_tcpSyn: meta.syncounter1 = {}", {meta.syncounter1});
        log_msg("count_tcpSyn: meta.syncounter2 = {}", {meta.syncounter2});
        log_msg("count_tcpSyn: meta.syncounter3 = {}", {meta.syncounter3});
        log_msg("count_tcpSyn: meta.syncounter4 = {}", {meta.syncounter4});
    }

    action reset_tcpSyn() {
     	meta.syncounter1 = 0;
     	meta.syncounter2 = 0;
     	meta.syncounter3 = 0;
     	meta.syncounter4 = 0;
        ingress_syn_register1.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        ingress_syn_register2.write((bit<32>)meta.synhashindex2, meta.syncounter2);
        ingress_syn_register3.write((bit<32>)meta.synhashindex3, meta.syncounter3);
        ingress_syn_register4.write((bit<32>)meta.synhashindex4, meta.syncounter4);


        log_msg("decrease_tcpSyn: meta.syncounter1 = {}", {meta.syncounter1});
        log_msg("decrease_tcpSyn: meta.syncounter2 = {}", {meta.syncounter2});
        log_msg("decrease_tcpSyn: meta.syncounter3 = {}", {meta.syncounter3});
        log_msg("decrease_tcpSyn: meta.syncounter4 = {}", {meta.syncounter4});
    }


    /* ---- COUNT ICMP ---- */
    action count_icmp() {
        meta.icmpcounter1 = meta.icmpcounter1 + 1;
        meta.icmpcounter2 = meta.icmpcounter2 + 1;
        meta.icmpcounter3 = meta.icmpcounter3 + 1;
        meta.icmpcounter4 = meta.icmpcounter4 + 1;

        ingress_icmp_register1.write((bit<32>)meta.icmphashindex1, meta.icmpcounter1);
        ingress_icmp_register2.write((bit<32>)meta.icmphashindex2, meta.icmpcounter2);
        ingress_icmp_register3.write((bit<32>)meta.icmphashindex3, meta.icmpcounter3);
        ingress_icmp_register4.write((bit<32>)meta.icmphashindex4, meta.icmpcounter4);

        log_msg("count_icmp: meta.icmpcounter1 = {}", {meta.icmpcounter1});
        log_msg("count_icmp: meta.icmpcounter2 = {}", {meta.icmpcounter2});
        log_msg("count_icmp: meta.icmpcounter3 = {}", {meta.icmpcounter3});
        log_msg("count_icmp: meta.icmpcounter4 = {}", {meta.icmpcounter4});
    }

    action reset_icmp() {
        meta.icmpcounter1 = 0;
        meta.icmpcounter2 = 0;
        meta.icmpcounter3 = 0;
        meta.icmpcounter4 = 0;
    

        ingress_icmp_register1.write((bit<32>)meta.icmphashindex1, 0);
        ingress_icmp_register2.write((bit<32>)meta.icmphashindex2, 0);
        ingress_icmp_register3.write((bit<32>)meta.icmphashindex3, 0);
        ingress_icmp_register4.write((bit<32>)meta.icmphashindex4, 0);

        log_msg("reset_icmp: meta.icmpcounter1 = {}", {meta.icmpcounter1});
        log_msg("reset_icmp: meta.icmpcounter2 = {}", {meta.icmpcounter2});
        log_msg("reset_icmp: meta.icmpcounter3 = {}", {meta.icmpcounter3});
        log_msg("reset_icmp: meta.icmpcounter4 = {}", {meta.icmpcounter4});
    }


    /* ---- MANAGE ICMP TIMESTAMP ---- */
    action update_timestamp() {
        ingress_timestamp_register1.write((bit<32>)meta.icmphashindex1, standard_metadata.ingress_global_timestamp);
        ingress_timestamp_register2.write((bit<32>)meta.icmphashindex2, standard_metadata.ingress_global_timestamp);
        ingress_timestamp_register3.write((bit<32>)meta.icmphashindex3, standard_metadata.ingress_global_timestamp);
        ingress_timestamp_register4.write((bit<32>)meta.icmphashindex4, standard_metadata.ingress_global_timestamp);

        log_msg("update_timestamp : {}", {standard_metadata.ingress_global_timestamp});
    }


    /* ----- TABLES ----- */
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

    table SYN_count_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            count_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = count_tcpSyn();
    }


    table SYN_reset_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            reset_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = reset_tcpSyn();
    }

    table ICMP_count_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            count_icmp;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = count_icmp();
    }

    table ICMP_reset_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            reset_icmp;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = reset_icmp();
    }

    table ICMP_timestamp_update_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            update_timestamp;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = update_timestamp();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            log_msg("INGRESS.hdr.ipv4.srcAddr{}", {hdr.ipv4.srcAddr});
            log_msg("INGRESS.hdr.ipv4.dstAddr = {}", {hdr.ipv4.dstAddr});


            meta.srcAddr = hdr.ipv4.srcAddr;

            ipv4_lpm.apply();


            // Check if packet is ICMP
            if (hdr.ipv4.protocol == IP_PROTOCOL_ICMP) {

                // Generate meta.icmphashindex1 for ICMP bloom filter index
                hash(  meta.icmphashindex1,
                        HashAlgorithm.crc32,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );

                // Generate meta.icmphashindex2 for ICMP bloom filter index
                hash(  meta.icmphashindex2,
                        HashAlgorithm.crc16,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );

                // Generate meta.icmphashindex3 for ICMP bloom filter index
                hash(  meta.icmphashindex3,
                        HashAlgorithm.xor16,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );

                // Generate meta.icmphashindex4 for ICMP bloom filter index
                hash(  meta.icmphashindex4,
                        HashAlgorithm.identity,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );


                // Read current counters
                ingress_icmp_register1.read(meta.icmpcounter1, (bit<32>)meta.icmphashindex1);
                ingress_icmp_register2.read(meta.icmpcounter2, (bit<32>)meta.icmphashindex2);
                ingress_icmp_register3.read(meta.icmpcounter3, (bit<32>)meta.icmphashindex3);
                ingress_icmp_register4.read(meta.icmpcounter4, (bit<32>)meta.icmphashindex4);
                

                // Read current timestamps
                ingress_timestamp_register1.read(meta.icmptimestamp1, (bit<32>)meta.icmphashindex1);
                ingress_timestamp_register2.read(meta.icmptimestamp2, (bit<32>)meta.icmphashindex2);
                ingress_timestamp_register3.read(meta.icmptimestamp3, (bit<32>)meta.icmphashindex3);
                ingress_timestamp_register4.read(meta.icmptimestamp4, (bit<32>)meta.icmphashindex4);


                // ICMP Count
                ICMP_count_table.apply();


                // Check if timestamp exceeds time threshold
                if (standard_metadata.ingress_global_timestamp > (meta.icmptimestamp1 + ICMP_TIMESTAMP_TRESHOLD) ||  
                    standard_metadata.ingress_global_timestamp > (meta.icmptimestamp2 + ICMP_TIMESTAMP_TRESHOLD) ||
                    standard_metadata.ingress_global_timestamp > (meta.icmptimestamp3 + ICMP_TIMESTAMP_TRESHOLD) ||  
                    standard_metadata.ingress_global_timestamp > (meta.icmptimestamp4 + ICMP_TIMESTAMP_TRESHOLD) ||
                    meta.icmpcounter1 > ICMP_RESET_THRESHOLD ||
                    meta.icmpcounter2 > ICMP_RESET_THRESHOLD || 
                    meta.icmpcounter3 > ICMP_RESET_THRESHOLD ||
                    meta.icmpcounter4 > ICMP_RESET_THRESHOLD
                ) {
                    // Reset ICMP counters
                    ICMP_reset_table.apply();
                }


                // Update timestamp
                ICMP_timestamp_update_table.apply();

                
                // Check if ICMP counters exceeds time threshold
                if (meta.icmpcounter1 == 1 ||
                    meta.icmpcounter2 == 1 || 
                    meta.icmpcounter3 == 1 ||
                    meta.icmpcounter4 == 1 || 
                    (meta.icmpcounter1 > ICMP_PACKETS_THRESHOLD && 
                    meta.icmpcounter2 > ICMP_PACKETS_THRESHOLD &&
                    meta.icmpcounter3 > ICMP_PACKETS_THRESHOLD && 
                    meta.icmpcounter4 > ICMP_PACKETS_THRESHOLD)
                ) {
                    // Drop packet
                    drop();
                }
            }


            if (hdr.tcp.isValid()) {
                log_msg("INGRESS.hdr.tcp.dstPort = {}", {hdr.tcp.dstPort});

                // Generate meta.synhashindex1 for SYN bloom filter index
                hash(  meta.synhashindex1,
                        HashAlgorithm.crc32,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );
                // Generate meta.synhashindex2 for SYN bloom filter index
                hash(  meta.synhashindex2,
                        HashAlgorithm.xor16,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );
                // Generate meta.synhashindex3 for SYN bloom filter index
                hash(  meta.synhashindex3,
                        HashAlgorithm.crc16,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );
                // Generate meta.synhashindex4 for SYN bloom filter index
                hash(  meta.synhashindex4,
                        HashAlgorithm.identity,
                        16w0,
                        {hdr.ipv4.srcAddr},
                        16w65535
                );


                // Fetch current Open Connection counters
                ingress_syn_register1.read(meta.syncounter1, (bit<32>)meta.synhashindex1);
                ingress_syn_register2.read(meta.syncounter2, (bit<32>)meta.synhashindex2);
                ingress_syn_register3.read(meta.syncounter3, (bit<32>)meta.synhashindex3);
                ingress_syn_register4.read(meta.syncounter4, (bit<32>)meta.synhashindex4);


                // ACK
                if (hdr.tcp.ack == 1 &&
                    hdr.tcp.syn == 0 || 
                    (meta.syncounter1 > TCP_SYN_RESET_TRESHOLD ||
                    meta.syncounter2 > TCP_SYN_RESET_TRESHOLD ||
                    meta.syncounter3 > TCP_SYN_RESET_TRESHOLD ||
                    meta.syncounter4 > TCP_SYN_RESET_TRESHOLD)
                    )  {
                    log_msg("TCP ACK");

                    // If ACK flag is set to 1 or limit has been reached then reset SYN counter
                    SYN_reset_table.apply();
                }
                

                // SYN request
                else if (hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                    log_msg("TCP SYN");

                    log_msg("INGRESS.Apply meta.syncounter1 = {}", {meta.syncounter1});
                    log_msg("INGRESS.Apply meta.syncounter2 = {}", {meta.syncounter2});

                    SYN_count_table.apply();
                    if (meta.syncounter1 == 1 || meta.syncounter2 == 1 || meta.syncounter3 == 1 || meta.syncounter4 == 1) {
                        drop();
                    } else if (meta.syncounter1 > TCP_SYN_DROP_TRESHOLD || 
                                meta.syncounter2 > TCP_SYN_DROP_TRESHOLD || 
                                meta.syncounter3 > TCP_SYN_DROP_TRESHOLD || 
                                meta.syncounter4 > TCP_SYN_DROP_TRESHOLD
                            ) {
                        drop();
                    }
                }
            }
         }
    }

}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action egress_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    table egress_ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            egress_ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


     apply {

         if (hdr.ipv4.isValid()) {
            egress_ipv4_lpm.apply();
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
        packet.emit(hdr.icmp);
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
