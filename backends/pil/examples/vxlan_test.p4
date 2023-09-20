#include <core.p4>
#include <dpdk/pna.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

typedef bit<12> vlan_id_t;
typedef bit<48> ethernet_addr_t;

struct empty_metadata_t {
}

header ethernet_t {
    ethernet_addr_t dst_addr;
    ethernet_addr_t src_addr;
    bit<16>         ether_type;
}

header vlan_tag_t {
    bit<3> pri;
    bit<1> cfi;
    vlan_id_t vlan_id;
    bit<16> eth_type;
}

header ipv4_t {
    bit<8> ver_ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_hdr;
    bit<8>   hoplimit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header bridged_md_t {
    bit<32> ingress_port;
}

struct headers_t {
    bridged_md_t bridged_meta;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t  tcp;
    udp_t  udp;
}

struct mac_learn_digest_t {
    ethernet_addr_t mac_addr;
    PortId_t        port;
    vlan_id_t       vlan_id;
}

struct local_metadata_t {
    bool               send_mac_learn_msg;
    mac_learn_digest_t mac_learn_msg;
    bit<16>            l4_sport;
    bit<16>            l4_dport;
}

parser packet_parser(packet_in packet, out headers_t headers, inout local_metadata_t local_metadata, in pna_main_parser_input_metadata_t standard_metadata) {
    InternetChecksum() ck;
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            // ETHERTYPE_VLAN : parse_vlan;
            default: accept;
        }
    }

    // state parse_vlan {
    //     packet.extract(headers.vlan_tag);
    //     transition select(headers.vlan_tag.eth_type * 4) {
    //         ETHERTYPE_IPV4: parse_ipv4;
    //         default: accept;
    //     }
    // }

    state parse_ipv4 {
        packet.extract(headers.ipv4);

        ck.subtract(headers.ipv4.hdr_checksum);
        ck.subtract({/* 16-bit word */ headers.ipv4.ttl, headers.ipv4.protocol });
        headers.ipv4.hdr_checksum = ck.get();

        transition select(headers.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(headers.ipv6);

        ck.clear();
        ck.subtract({
            /* 16-bit words 0-7  */ headers.ipv6.src_addr,
            /* 16-bit words 8-15 */ headers.ipv6.dst_addr
        });
        transition select(headers.ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(headers.tcp);
        local_metadata.l4_sport = headers.tcp.sport;
        local_metadata.l4_dport = headers.tcp.dport;
        transition accept;
    }

    state parse_udp {
        packet.extract(headers.udp);
        local_metadata.l4_sport = headers.udp.sport;
        local_metadata.l4_dport = headers.udp.dport;
        transition accept;
    }
}

control packet_deparser(packet_out packet, in headers_t headers, in local_metadata_t local_metadata, in pna_main_output_metadata_t ostd) {
    apply {
        packet.emit(headers.bridged_meta);
        packet.emit(headers.ethernet);
        packet.emit(headers.vlan_tag);
        packet.emit(headers.ipv4);
        packet.emit(headers.tcp);
        packet.emit(headers.udp);
    }
}

control PreControlImpl(
    in    headers_t  hdr,
    inout local_metadata_t meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply {
    }
}

//
// Control block.
//
control MainControlImpl(
	inout headers_t hdrs,
	inout local_metadata_t meta,
	in    pna_main_input_metadata_t  istd,
	inout pna_main_output_metadata_t ostd)
{
        action empty() {
        }
        apply {}
}

PNA_NIC(packet_parser(), PreControlImpl(), MainControlImpl(), packet_deparser()) main;

