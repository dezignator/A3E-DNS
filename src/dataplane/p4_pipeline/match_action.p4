/* ============================================================
 * A3E-DNS — P4 Stage 2: Match-Action
 * Thesis §6.12.2
 * ============================================================
 *
 * Responsibilities (§6.12.2):
 *   - flow-level features: packet length distribution, timing,
 *     protocol attributes, communication statistics
 *   - maintain per-flow counters and registers
 *   - forward forwarding decisions unchanged (the pipeline must not
 *     modify the forwarding path)
 *
 * The match-action tables are programmable so that the features can
 * be extended with software updates without changing the data plane.
 *
 * Compile with:
 *   p4c --target bmv2 --arch v1model --std p4-16 match_action.p4
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* Per-flow counters and feature registers. */
const bit<32> FEATURE_MAX_FLOWS = 1024;

header parsed_meta_t {
    bit<8>  protocol_id;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  ip_proto;
    bit<32> src_ip;
    bit<32> dst_ip;
}

struct headers_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    parsed_meta_t   parsed;
}

struct parser_metadata_t {
    parsed_meta_t parsed;
}

/* Per-flow register slot. */
struct flow_state_t {
    bit<64> packet_count;
    bit<64> byte_count;
    bit<64> last_ts;        /* ns since epoch, as observed at ingress */
    bit<32> min_length;
    bit<32> max_length;
}

register<flow_state_t>(FEATURE_MAX_FLOWS) flow_state;

/* Match-action table for feature extraction. The exact match key is
 * the 5-tuple; the action updates the per-flow state. */
action update_features(bit<32> pkt_len, bit<64> ts_ns, bit<32> index) {
    flow_state_t s = flow_state.read(index);
    s.packet_count = s.packet_count + 1;
    s.byte_count   = s.byte_count + pkt_len;
    s.last_ts      = ts_ns;
    if (pkt_len < s.min_length) { s.min_length = pkt_len; }
    if (pkt_len > s.max_length) { s.max_length = pkt_len; }
    flow_state.write(index, s);
}

table feature_table {
    key = {
        hdr.parsed.src_ip   : exact;
        hdr.parsed.dst_ip   : exact;
        hdr.parsed.src_port : exact;
        hdr.parsed.dst_port : exact;
        hdr.parsed.ip_proto : exact;
    }
    actions = {
        update_features;
        NoAction;
    }
    size = FEATURE_MAX_FLOWS;
    default_action = NoAction();
}

control IngressImpl(inout headers_t hdr,
                    inout parser_metadata_t meta,
                    inout standard_metadata_t std_meta)
{
    apply {
        if (hdr.parsed.isValid()) {
            bit<32> len = (bit<32>) std_meta.packet_length;
            bit<64> ts  = (bit<64>) std_meta.ingress_global_timestamp;
            bit<32> idx = hash5tuple();
            feature_table.apply();
            update_features(len, ts, idx);
        }
    }
}

/* Hash the 5-tuple to a slot index. */
bit<32> hash5tuple() {
    bit<32> h = hdr.parsed.src_ip ^ hdr.parsed.dst_ip;
    h = h ^ ((bit<32>) hdr.parsed.src_port << 16);
    h = h ^ ((bit<32>) hdr.parsed.dst_port);
    h = h ^ ((bit<32>) hdr.parsed.ip_proto);
    return h & (FEATURE_MAX_FLOWS - 1);
}

control EgressImpl(inout headers_t hdr,
                   inout parser_metadata_t meta,
                   inout standard_metadata_t std_meta)
{
    apply {}
}

control VerifyChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) { apply {} }
control ComputeChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) { apply {} }

parser ParserImpl(packet_in packet,
                  out headers_t hdr,
                  inout parser_metadata_t meta,
                  inout standard_metadata_t std_meta)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
