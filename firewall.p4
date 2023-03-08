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
    bit<32>    syncounter1;
    bit<32>    syncounter2;
    bit<32>    droppedcounter1;
    bit<32>    droppedcounter2;
    bit<32>    icmpcounter1;
    bit<32>    icmpcounter2;

    bit<1>     balcklistIP1;
    bit<1>     balcklistIP2;
    bit<32>    icmptimestamp1;
    bit<32>    icmptimestamp2;
  
    bit<10>    synhashindex1;
    bit<10>    synhashindex2;
    bit<10>    icmphashindex1;
    bit<10>    icmphashindex2;
    bit<10>    srcIpHash1;
    bit<10>    srcIpHash2;

    bit<32>    portNumber;
    bit<32>    routerPort;
    bit<32>    portLimit;
    bit<1>     isSYN;
    bit<1>     isACK;
    bit<32>    localNetwork;
    bit<1>     localNetworkOriginated;
    bit<32>    srcAddr;
    
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}

register <bit<1>>(1024) blacklist_register;


// SYN Flood Ingress Bloom Filters
register <bit<32>>(1024) ingress_syn_register;
register <bit<32>>(1024) ingress_dropped_register;
//register <bit<32>>(1024) ingress_timestamp_register;
register <bit<32>>(1024) ingress_victimIp_register;
register <bit<32>>(1024) ingress_victimPort_register;

// SYN Flood Egress Bloom Filters
register <bit<32>>(1024) egress_syn_register;
register <bit<32>>(1024) egress_victimIp_register;
register <bit<32>>(1024) egress_victimPort_register;


// ICMP Flood Ingress Bloom Filters
register <bit<32>>(1024) ingress_icmp_register;
register <bit<32>>(1024) ingress_timestamp_register;


const bit<32> DROPPED_PACKETS_TRESHOLD = 10;
const bit<32> OPEN_CONNECTIONS_TRESHOLD = 5;
const bit<32> ICMP_TIMESTAMP_TRESHOLD = 50000;
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

    action count_tcpSyn() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.syncounter1 = meta.syncounter1 + 1;
        meta.syncounter2 = meta.syncounter2 + 1;
        ingress_syn_register.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        ingress_syn_register.write((bit<32>)meta.synhashindex2, meta.syncounter2);
    }

    action decrease_tcpSyn() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        if (meta.syncounter1 > 0 && meta.syncounter2 > 0) {
            meta.syncounter1 = meta.syncounter1 - 1;
            meta.syncounter2 = meta.syncounter2 - 1;
        }

        ingress_syn_register.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        ingress_syn_register.write((bit<32>)meta.synhashindex2, meta.syncounter2);
    }

    action count_icmp() {
        log_msg("count_icmp: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_icmp: meta.routerPort = {}", {meta.routerPort});

        meta.icmpcounter1 = meta.icmpcounter1 + 1;
        meta.icmpcounter2 = meta.icmpcounter2 + 1;
        ingress_icmp_register.write((bit<32>)meta.icmphashindex1, meta.icmpcounter1);
        ingress_icmp_register.write((bit<32>)meta.icmphashindex2, meta.icmpcounter2);
    }

    action reset_icmp() {
        log_msg("count_icmp: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_icmp: meta.routerPort = {}", {meta.routerPort});

        if (meta.icmpcounter1 > 0 && meta.icmpcounter2 > 0) {
            meta.icmpcounter1 = 0;
            meta.icmpcounter2 = 0;
        }

        ingress_icmp_register.write((bit<32>)meta.icmphashindex1, 0);
        ingress_icmp_register.write((bit<32>)meta.icmphashindex2, 0);
    }

    action update_timestamp() {
        log_msg("count_icmp: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_icmp: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_icmp: meta.routerPort = {}", {meta.routerPort});

        ingress_timestamp_register.write((bit<32>)meta.icmphashindex1, standard_metadata.enq_timestamp);
        ingress_timestamp_register.write((bit<32>)meta.icmphashindex2, standard_metadata.enq_timestamp);
    }

    action count_dropped() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.droppedcounter1 = meta.droppedcounter1 + 1;
        meta.droppedcounter2 = meta.droppedcounter2 + 1;
        ingress_dropped_register.write((bit<32>)meta.synhashindex1, meta.droppedcounter1);
        ingress_dropped_register.write((bit<32>)meta.synhashindex2, meta.droppedcounter1);
    }

    action reset_dropped() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});


        ingress_dropped_register.write((bit<32>)meta.synhashindex1, 0);
        ingress_dropped_register.write((bit<32>)meta.synhashindex2, 0);
    }

    action add_to_blacklist() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.droppedcounter1 = meta.droppedcounter1 + 1;
        meta.droppedcounter2 = meta.droppedcounter2 + 1;
        blacklist_register.write((bit<32>)meta.srcIpHash1, 1);
        blacklist_register.write((bit<32>)meta.srcIpHash2, 1);
    }

    action remove_from_blacklist() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        blacklist_register.write((bit<32>)meta.srcIpHash1, 0);
        blacklist_register.write((bit<32>)meta.srcIpHash2, 0);
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

    table blacklist_add {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }

        actions = {
            add_to_blacklist;
            NoAction;
            drop;
        }
        default_action = add_to_blacklist();
    }

    table blacklist_remove {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }

        actions = {
            remove_from_blacklist;
            NoAction;
            drop;
        }
        default_action = remove_from_blacklist();
    }

    table SYN_count_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
        }
        actions = {
            count_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = count_tcpSyn();
    }


    table SYN_decrease_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
        }
        actions = {
            decrease_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = decrease_tcpSyn();
    }

    table ICMP_count_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
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
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
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
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
        }
        actions = {
            update_timestamp;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = update_timestamp();
    }

    table dropped_count_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
        }
        actions = {
            count_dropped;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = count_dropped();
    }


    table dropped_reset_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
        }
        actions = {
            reset_dropped;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = reset_dropped();
    }

    table KnownVictim_table{
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop();
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        meta.portLimit = 3;

         if (hdr.ipv4.isValid()) {
            meta.srcAddr = hdr.ipv4.srcAddr;

            // Generate meta.srcIpHash1 for blacklist index
            hash(  meta.srcIpHash1,
                        HashAlgorithm.crc32,
                        10w0,
                        {hdr.ipv4.srcAddr},
                        10w1023
                );
            // Generate meta.srcIpHash2 for blacklist index
            hash(  meta.srcIpHash2,
                        HashAlgorithm.crc16,
                        10w0,
                        {hdr.ipv4.srcAddr},
                        10w1023
                );

            // Read blacklist at indexs generated
            blacklist_register.read(meta.balcklistIP1, (bit<32>)meta.srcIpHash1);
            blacklist_register.read(meta.balcklistIP2, (bit<32>)meta.srcIpHash2);

            //If ip in blacklist then drop
            if (meta.balcklistIP1 == 1 && meta.balcklistIP2 == 1) {
                drop();
            } else {
                ipv4_lpm.apply();

                // Generate meta.icmphashindex1 for ICMP bloom filter index
                hash(  meta.icmphashindex1,
                        HashAlgorithm.crc32,
                        10w0,
                        {hdr.ipv4.dstAddr},
                        10w1023
                );
                // Generate meta.icmphashindex2 for ICMP bloom filter index
                hash(  meta.icmphashindex2,
                        HashAlgorithm.crc16,
                        10w0,
                        {hdr.ipv4.dstAddr},
                        10w1023
                );

                // Check if packet is ICMP 
                if (hdr.ipv4.protocol == IP_PROTOCOL_ICMP) {
                    // Read current counters
                    ingress_icmp_register.read(meta.icmpcounter1, (bit<32>)meta.icmphashindex1);
                    ingress_icmp_register.read(meta.icmpcounter2, (bit<32>)meta.icmphashindex2);

                    //Count 
                    ICMP_count_table.apply();

                    // Read current timestamps
                    ingress_timestamp_register.read(meta.icmptimestamp1, (bit<32>)meta.icmphashindex1);
                    ingress_timestamp_register.read(meta.icmptimestamp2, (bit<32>)meta.icmphashindex2);

                    if (meta.icmptimestamp1 > ICMP_TIMESTAMP_TRESHOLD && meta.icmptimestamp2 >  ICMP_TIMESTAMP_TRESHOLD) {
                        ICMP_reset_table.apply();
                    } 

                    ICMP_timestamp_update_table.apply();
                }

                if (hdr.tcp.isValid()) {

                    // Generate meta.synhashindex1 for SYN bloom filter index
                    hash(  meta.synhashindex1,
                            HashAlgorithm.crc32,
                            10w0,
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
                            10w1023
                    );
                    // Generate meta.synhashindex2 for SYN bloom filter index
                    hash(  meta.synhashindex2,
                            HashAlgorithm.crc16,
                            10w0,
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
                            10w1023
                    );

                    // ACK
                    //if (((hdr.tcp.flags >> 1) & 1) != 0) {
                    if (hdr.tcp.ack == 1) {
                        // If ACK flag is set to 1 then decrease counter
                        SYN_decrease_table.apply();
                        log_msg("TCP ACK");

                        // If count is less than threshold/2 then remove from blacklist
                        if ((meta.syncounter1 > (OPEN_CONNECTIONS_TRESHOLD/2)) && (meta.syncounter2 > (OPEN_CONNECTIONS_TRESHOLD/2))){
                            blacklist_remove.apply();
                        }
                    }

                    //SYN request
                    //if (((hdr.tcp.flags >> 4) & 1) != 0) {
                    if (hdr.tcp.syn == 1) {
                        log_msg("TCP request = SYN");


                        // Is this a known attacker?
                        ingress_syn_register.read(meta.syncounter1, (bit<32>)meta.synhashindex1);
                        ingress_syn_register.read(meta.syncounter2, (bit<32>)meta.synhashindex2);
                        log_msg("INGRESS.hdr.ipv4.srcAddr{}", {hdr.ipv4.srcAddr});
                        log_msg("INGRESS.hdr.ipv4.dstAddr = {}", {hdr.ipv4.dstAddr});
                        log_msg("INGRESS.hdr.tcp.dstPort = {}", {hdr.tcp.dstPort});
                        log_msg("INGRESS.Apply meta.syncounter1 = {}", {meta.syncounter1});
                        log_msg("INGRESS.Apply meta.syncounter2 = {}", {meta.syncounter2});
                        log_msg("INGRESS.Apply meta.portLimit = {}", {meta.portLimit});
                        if ((meta.syncounter1 > OPEN_CONNECTIONS_TRESHOLD) && (meta.syncounter2 > OPEN_CONNECTIONS_TRESHOLD)){
                            log_msg("The attacker is: {}", {hdr.ipv4.srcAddr});
                            log_msg("The targeted DoS IP: {}", {hdr.ipv4.dstAddr});
                            log_msg("The targeted DoS UDP: {}", {hdr.tcp.dstPort});
                            ingress_victimIp_register.write((bit<32>)meta.synhashindex1, hdr.ipv4.dstAddr);
                            ingress_victimPort_register.write((bit<32>)meta.synhashindex1, (bit<32>)hdr.tcp.dstPort);
                            ingress_dropped_register.read(meta.droppedcounter1, (bit<32>)meta.synhashindex1);
                            ingress_dropped_register.read(meta.droppedcounter2, (bit<32>)meta.synhashindex2);
                            dropped_count_table.apply();
                            ingress_dropped_register.read(meta.droppedcounter1, (bit<32>)meta.synhashindex1);
                            ingress_dropped_register.read(meta.droppedcounter2, (bit<32>)meta.synhashindex2);
                            if ((meta.droppedcounter1 > DROPPED_PACKETS_TRESHOLD) && (meta.droppedcounter2 > DROPPED_PACKETS_TRESHOLD)){
                                blacklist_add.apply();
                            }
                            drop();
                        }

                        SYN_count_table.apply();
                    }
                }
            }
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
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.syncounter1 = meta.syncounter1 + 1;
        meta.syncounter2 = meta.syncounter2 + 1;
        egress_syn_register.write((bit<32>)meta.synhashindex1, meta.syncounter1);
        egress_syn_register.write((bit<32>)meta.synhashindex2, meta.syncounter2);
    }

    action egress_decrease_tcpSyn() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

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
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
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
            //meta.portLimit: exact;
            //hdr.tcp.flags: exact;
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
        meta.portLimit = 3;

         if (hdr.ipv4.isValid()) {

            //KnownVictim_table.apply();

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
                //if (((hdr.tcp.flags >> 1) & 1) != 0) {
                if (hdr.tcp.ack == 1) {
                    egress_SYN_decrease_table.apply();
                    log_msg("TCP ACK");
                }

                //SYN request
                //if (((hdr.tcp.flags >> 4) & 1) != 0) {
                if (hdr.tcp.syn == 1) {
                    log_msg("TCP request = SYN");


                    // Is this a known attacker?
                    egress_syn_register.read(meta.syncounter1, (bit<32>)meta.synhashindex1);
                    egress_syn_register.read(meta.syncounter2, (bit<32>)meta.synhashindex2);
                    log_msg("INGRESS.hdr.ipv4.srcAddr{}", {hdr.ipv4.srcAddr});
                    log_msg("INGRESS.hdr.ipv4.dstAddr = {}", {hdr.ipv4.dstAddr});
                    log_msg("INGRESS.hdr.tcp.dstPort = {}", {hdr.tcp.dstPort});
                    log_msg("INGRESS.Apply meta.syncounter1 = {}", {meta.syncounter1});
                    log_msg("INGRESS.Apply meta.syncounter2 = {}", {meta.syncounter2});
                    log_msg("INGRESS.Apply meta.portLimit = {}", {meta.portLimit});
                    if ((meta.syncounter1 > EGRESS_SYN_TRESHOLD) && (meta.syncounter2 > EGRESS_SYN_TRESHOLD)){
                        log_msg("The attacker is: {}", {hdr.ipv4.srcAddr});
                        log_msg("The targeted DoS IP: {}", {hdr.ipv4.dstAddr});
                        log_msg("The targeted DoS UDP: {}", {hdr.tcp.dstPort});
                        egress_victimIp_register.write((bit<32>)meta.synhashindex1, hdr.ipv4.dstAddr);
                        egress_victimPort_register.write((bit<32>)meta.synhashindex1, (bit<32>)hdr.tcp.dstPort);
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
