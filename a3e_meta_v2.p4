/* A3E-DNS v2: BMv2 (v1model) program that classifies encrypted-DNS transports and keeps
 * per-flow packet/byte registers (Section 6.11.1 programmable switches).
 * NOT COMPILED IN THE ENVIRONMENT THAT PRODUCED THIS FILE. Build: p4c-bm2-ss a3e_meta_v2.p4 */
#include <core.p4>
#include <v1model.p4>

typedef bit<48> mac_t; typedef bit<32> ip4_t;
header ethernet_t { mac_t dst; mac_t src; bit<16> ether_type; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len; bit<16> id; bit<3> flags; bit<13> frag;
                bit<8> ttl; bit<8> protocol; bit<16> checksum; ip4_t src; ip4_t dst; }
header l4_t { bit<16> sport; bit<16> dport; }
struct headers_t { ethernet_t eth; ipv4_t ip; l4_t l4; }
struct meta_t { bit<2> proto; bit<16> idx; bit<32> pkts; bit<32> bytes; }

parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t s) {
    state start { pkt.extract(h.eth); transition select(h.eth.ether_type) { 0x0800: ip; default: accept; } }
    state ip { pkt.extract(h.ip); transition select(h.ip.protocol) { 6: l4; 17: l4; default: accept; } }
    state l4 { pkt.extract(h.l4); transition accept; }
}
control VC(inout headers_t h, inout meta_t m) { apply { } }
control I(inout headers_t h, inout meta_t m, inout standard_metadata_t s) {
    register<bit<32>>(65536) pkt_reg; register<bit<32>>(65536) byte_reg;
    action set_proto(bit<2> p) { m.proto = p; }
    action fwd(bit<9> port) { s.egress_spec = port; }
    action drop() { mark_to_drop(s); }
    table classify { key = { h.ip.protocol: exact; h.l4.dport: exact; } actions = { set_proto; NoAction; } size = 16; default_action = NoAction(); }
    table l3 { key = { h.ip.dst: lpm; } actions = { fwd; drop; } size = 256; default_action = drop(); }
    apply {
        if (h.ip.isValid() && h.l4.isValid()) {
            classify.apply();
            hash(m.idx, HashAlgorithm.crc16, 16w0, { h.ip.src, h.ip.dst, h.l4.sport, h.l4.dport, h.ip.protocol }, 32w65536);
            pkt_reg.read(m.pkts, (bit<32>) m.idx); m.pkts = m.pkts + 1; pkt_reg.write((bit<32>) m.idx, m.pkts);
            byte_reg.read(m.bytes, (bit<32>) m.idx); m.bytes = m.bytes + (bit<32>) h.ip.total_len; byte_reg.write((bit<32>) m.idx, m.bytes);
            if (m.proto != 0) { h.ip.diffserv = (bit<8>) m.proto << 2; }   // tag transport class for downstream stages
            l3.apply();
        }
    }
}
control E(inout headers_t h, inout meta_t m, inout standard_metadata_t s) { apply { } }
control CC(inout headers_t h, inout meta_t m) { apply { update_checksum(h.ip.isValid(), { h.ip.version, h.ip.ihl, h.ip.diffserv, h.ip.total_len, h.ip.id, h.ip.flags, h.ip.frag, h.ip.ttl, h.ip.protocol, h.ip.src, h.ip.dst }, h.ip.checksum, HashAlgorithm.csum16); } }
control D(packet_out pkt, in headers_t h) { apply { pkt.emit(h.eth); pkt.emit(h.ip); pkt.emit(h.l4); } }
V1Switch(P(), VC(), I(), E(), CC(), D()) main;
