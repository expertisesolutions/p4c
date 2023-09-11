#include <core.p4>
#include <dpdk/pna.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
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
            ETHERTYPE_VLAN : parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(headers.vlan_tag);
        transition select(headers.vlan_tag.eth_type * 4) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

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
/*
control ingress(inout headers_t headers, inout local_metadata_t local_metadata1, in psa_ingress_input_metadata_t standard_metadata, inout psa_ingress_output_metadata_t ostd) {
    InternetChecksum() csum; 
    action vxlan_encap(
        bit<48> ethernet_dst_addr,
        bit<48> ethernet_src_addr,
        bit<16> ethernet_ether_type,
        bit<8> ipv4_ver_ihl,
        bit<8> ipv4_diffserv,
        bit<16> ipv4_total_len,
        bit<16> ipv4_identification,
        bit<16> ipv4_flags_offset,
        bit<8> ipv4_ttl,
        bit<8> ipv4_protocol,
        bit<16> ipv4_hdr_checksum,
        bit<32> ipv4_src_addr,
        bit<32> ipv4_dst_addr,
        bit<16> udp_src_port,
        bit<16> udp_dst_port,
        bit<16> udp_length,
        bit<16> udp_checksum,
        bit<8> vxlan_flags,
        bit<24> vxlan_reserved,
        bit<24> vxlan_vni,
        bit<8> vxlan_reserved2,
        bit<32> port_out
    ) {
        headers.outer_ethernet.src_addr = ethernet_src_addr;
        headers.outer_ethernet.dst_addr = ethernet_dst_addr;

        headers.outer_ethernet.ether_type = ethernet_ether_type;
        headers.outer_ipv4.ver_ihl = ipv4_ver_ihl; 
        headers.outer_ipv4.diffserv = ipv4_diffserv; 
        headers.outer_ipv4.total_len = ipv4_total_len; 
        headers.outer_ipv4.identification = ipv4_identification; 
        headers.outer_ipv4.flags_offset = ipv4_flags_offset; 
        headers.outer_ipv4.ttl = ipv4_ttl; 
        headers.outer_ipv4.protocol = ipv4_protocol; 
        headers.outer_ipv4.hdr_checksum = ipv4_hdr_checksum; 
        headers.outer_ipv4.src_addr = ipv4_src_addr; 
        headers.outer_ipv4.dst_addr = ipv4_dst_addr;
        headers.outer_udp.src_port = udp_src_port;
        headers.outer_udp.dst_port = udp_dst_port;
        headers.outer_udp.length = udp_length;
        headers.outer_udp.checksum = udp_checksum;
        headers.vxlan.flags = vxlan_flags;
        headers.vxlan.reserved = vxlan_reserved;
        headers.vxlan.vni = vxlan_vni;
        headers.vxlan.reserved2 = vxlan_reserved2;
        ostd.egress_port = (PortId_t)port_out;
        csum.add({headers.outer_ipv4.hdr_checksum, headers.ipv4.total_len});
        headers.outer_ipv4.hdr_checksum = csum.get();
        headers.outer_ipv4.total_len = headers.outer_ipv4.total_len + headers.ipv4.total_len;
        headers.outer_udp.length = headers.outer_udp.length + headers.ipv4.total_len;
    }
    action drop(){
        ostd.egress_port = (PortId_t)4;
    }
    table vxlan {
        key = {
            headers.ethernet.dst_addr: exact;
        }
        actions = {
            vxlan_encap;
            drop;
        }
        const default_action = drop;
        size =  1024 * 1024;
    }

    apply {
        vxlan.apply();
    }
}
*/

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

