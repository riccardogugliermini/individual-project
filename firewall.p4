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
    bit<32>    syncounter1;
    bit<32>    syncounter2;
    //bit<32>    byecounter;
    // bit<32>    byecounter2;
    bit<10>    hashindex1;
    bit<10>    hashindex2;
    bit<32>    portNumber;
    bit<32>    routerPort;
    bit<32>    portLimit;
    bit<1>     isSYN;
    bit<1>     isACK;
    bit<32>    localNetwork;
    bit<1>     localNetworkOriginated;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    icmp_t       icmp;
}

register <bit<32>>(1024) blacklist_register;
register <bit<32>>(1024) syn_register;
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

    //  action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    //     standard_metadata.egress_spec = port;
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    // }

    // action count_synConnection(){
    //     // Diagnostics
    //     meta.routerPort = 4;
    //     log_msg("count_synConnection: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
    //     log_msg("count_synConnection: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
    //     log_msg("count_synConnection: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
    //     log_msg("count_sipBye: meta.routerPort = {}", {meta.routerPort});

    //     // Not a known attacker. Count the invite
    //     meta.syncounter1 = meta.syncounter1 + 1;
    //     meta.syncounter2 = meta.syncounter2 + 1;
    //     syn_register.write((bit<32>)meta.hashindex1, meta.syncounter1);
    //     syn_register.write((bit<32>)meta.hashindex2, meta.syncounter2);

    // }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action checkLocalNetwork_action() {
        meta.localNetworkOriginated = 1;
    }

    action count_tcpSyn() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.syncounter1 = meta.syncounter1 + 1;
        meta.syncounter2 = meta.syncounter2 + 1;
        syn_register.write((bit<32>)meta.hashindex1, meta.syncounter1);
        syn_register.write((bit<32>)meta.hashindex2, meta.syncounter2);
    }

    action decrease_tcpSyn() {
        log_msg("count_tcpSyn: standard_metadata.ingress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_port = {}", {standard_metadata.ingress_port});
        log_msg("count_tcpSyn: standard_metadata.egress_spec = {}", {standard_metadata.egress_spec});
        log_msg("count_tcpSyn: meta.routerPort = {}", {meta.routerPort});

        meta.syncounter1 = meta.syncounter1 - 1;
        meta.syncounter2 = meta.syncounter2 - 1;
        syn_register.write((bit<32>)meta.hashindex1, meta.syncounter1);
        syn_register.write((bit<32>)meta.hashindex2, meta.syncounter2);
    }

    // action C2S_action(){
    //     const bit<48> INVITEstartline = 0x494e56495445;
    //     //meta.routerPort = 4;
    //     //-------------------------------
    //     // Direction: from CLIENT->SERVER
    //     //-------------------------------
    //     log_msg("count_sipBye: CLIENT->SERVER");

    //     // Generate meta.hashindex1 for bloom filter index
    //     hash(  meta.hashindex1,
    //             HashAlgorithm.crc32,
    //             10w0,
    //             {hdr.ipv4.dstAddr, hdr.udp.dstPort, standard_metadata.ingress_port, INVITEstartline},
    //             10w1023
    //     );
    //     // Generate meta.hashindex2 for bloom filter index
    //     hash(  meta.hashindex2,
    //             HashAlgorithm.crc16,
    //             10w0,
    //             {hdr.ipv4.dstAddr, hdr.udp.dstPort, standard_metadata.ingress_port, INVITEstartline},
    //             10w1023
    //     );

    //     // Reset invite_register at hashindex1 and hashindex2 location to 0
    //     // to indicate completion of INVITE-BYE pair
    //     invite_register.write((bit<32>)meta.hashindex1, 0);
    //     invite_register.write((bit<32>)meta.hashindex2, 0);
    // }

    action C2S_action() {
        const bit<48> SYNstartline = 0x53594e;
        log_msg("count_tcpAck: CLIENT->SERVER");

        hash(  meta.hashindex1,
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.dstAddr, hdr.tcp.dstPort, standard_metadata.ingress_port, SYNstartline},
                10w1023
        );

        hash(  meta.hashindex2,
                HashAlgorithm.crc16,
                10w0,
                {hdr.ipv4.dstAddr, hdr.tcp.dstPort, standard_metadata.ingress_port, SYNstartline},
                10w1023
        );

        syn_register.write((bit<32>)meta.hashindex1, 0);
        syn_register.write((bit<32>)meta.hashindex2, 0);
    }

    action S2C_action() {
        const bit<48> SYNstartline = 0x53594e;
        log_msg("count_tcpAck: SERVER->CLIENT");

        hash(  meta.hashindex1,
                HashAlgorithm.crc32,
                10w0,
                {hdr.ipv4.srcAddr, hdr.tcp.srcPort, standard_metadata.egress_spec, SYNstartline},
                10w1023
        );

        hash(  meta.hashindex2,
                HashAlgorithm.crc16,
                10w0,
                {hdr.ipv4.srcAddr, hdr.tcp.srcPort, standard_metadata.egress_spec, SYNstartline},
                10w1023
        );

        syn_register.write((bit<32>)meta.hashindex1, 0);
        syn_register.write((bit<32>)meta.hashindex2, 0);
    }

    action categorize_action(tcp_headers_t tcpHeaders){
        meta.isSYN = (bit<1>)((hdr.tcp.flags & 000010) != 0);
        meta.isACK = (bit<1>)((hdr.tcp.flags & 010000) != 0);
    }


    // action S2C_action(){
    //     const bit<48> INVITEstartline = 0x494e56495445;
    //     //meta.routerPort = 4;
    //     //-------------------------------
    //     // Direction: from SERVER->CLIENT
    //     //-------------------------------
    //     log_msg("count_sipBye: SERVER->CLIENT");

    //     // Generate meta.hashindex1 for bloom filter index, but with different HASH input to match
    //     // the original INVITE so that it produce the same index value
    //     hash(  meta.hashindex1,
    //             HashAlgorithm.crc32,
    //             10w0,
    //             {hdr.ipv4.srcAddr, hdr.udp.srcPort, standard_metadata.egress_spec, INVITEstartline},
    //             10w1023
    //     );
    //     // Generate meta.hashindex2 for bloom filter index, but with different HASH input to match
    //     // the original INVITE so that it produce the same index value
    //     hash(  meta.hashindex2,
    //             HashAlgorithm.crc16,
    //             10w0,
    //             {hdr.ipv4.srcAddr, hdr.udp.srcPort, standard_metadata.egress_spec, INVITEstartline},
    //             10w1023
    //     );

    //     // Reset invite_register at hashindex1 and hashindex2 location to 0
    //     // to indicate completion of INVITE-BYE pair
    //     invite_register.write((bit<32>)meta.hashindex1, 0);
    //     invite_register.write((bit<32>)meta.hashindex2, 0);
    // }

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
            NoAction;
            drop;
        }
        default_action = NoAction();
    }


    table SYN_count_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            hdr.tcp.flags: exact;
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
            hdr.tcp.flags: exact;
        }
        actions = {
            decrease_tcpSyn;
            drop;
            NoAction;
        }
        size = 1024;
        const default_action = decrease_tcpSyn();
    }

    table BYE_fromClient_toServer_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            hdr.tcp.flags: exact;
        }
        actions = {
            NoAction;
            C2S_action;
        }
        const default_action = NoAction();
    }

    table BYE_fromServer_toClient_table {
        key = {
            standard_metadata.ingress_port: exact;
            //meta.portLimit: exact;
            hdr.tcp.flags: exact;
        }
        actions = {
            NoAction;
            S2C_action;
        }
        const default_action = NoAction();
    }

    table categorizeTcp_table{
        key ={
            hdr.tcp.flags: exact;
        }
        actions = {
            categorize_action;
            NoAction;
        }
        default_action = NoAction();
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

            //KnownVictim_table.apply();

            ipv4_lpm.apply();

            if (hdr.tcp.isValid()) {

                // ACK
                if (((hdr.tcp.flags >> 1) & 1) != 0) {
                    SYN_decrease_table.apply();
                    log_msg("TCP ACK");
                }

                //SYN request
                if (((hdr.tcp.flags >> 4) & 1) != 0) {
                    log_msg("TCP request = SYN");

                    // Generate meta.hashindex1 for bloom filter index
                    hash(  meta.hashindex1,
                            HashAlgorithm.crc32,
                            10w0,
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
                            10w1023
                    );
                    // Generate meta.hashindex2 for bloom filter index
                    hash(  meta.hashindex2,
                            HashAlgorithm.crc16,
                            10w0,
                            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
                            10w1023
                    );

                    // Is this a known attacker?
                    syn_register.read(meta.syncounter1, (bit<32>)meta.hashindex1);
                    syn_register.read(meta.syncounter2, (bit<32>)meta.hashindex2);
                    log_msg("INGRESS.hdr.ipv4.srcAddr{}", {hdr.ipv4.srcAddr});
                    log_msg("INGRESS.hdr.ipv4.dstAddr = {}", {hdr.ipv4.dstAddr});
                    log_msg("INGRESS.hdr.tcp.dstPort = {}", {hdr.tcp.dstPort});
                    log_msg("INGRESS.Apply meta.syncounter1 = {}", {meta.syncounter1});
                    log_msg("INGRESS.Apply meta.syncounter2 = {}", {meta.syncounter2});
                    log_msg("INGRESS.Apply meta.portLimit = {}", {meta.portLimit});
                    if ((meta.syncounter1 > meta.portLimit) && (meta.syncounter2 > meta.portLimit)){
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
