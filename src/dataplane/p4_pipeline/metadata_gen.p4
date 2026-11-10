/* ============================================================
 * A3E-DNS — P4 Stage 3: Metadata Generation
 * Thesis §6.12.3
 * ============================================================
 *
 * Responsibilities (§6.12.3):
 *   - augment the extracted features into enriched packet metadata
 *   - forward ONLY the metadata (not the payload) to the telemetry
 *     interface consumed by the A3E-DNS framework
 *
 * This is the final stage of the three-stage pipeline. It reads the
 * per-flow state written by Stage 2 and emits a compact telemetry
 * record over a dedicated port (default 0x0A3E = "A3E").
 *
 * Compile with:
 *   p4c --target bmv2 --arch v1model --std p4-16 metadata_gen.p4
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

const bit<9> TELEMETRY_PORT = 0x0A3E;   /* 2622 */

header telemetry_t {
    bit<8>  protocol_id;
    bit<64> packet_count;
    bit<64> byte_count;
    bit<64> last_ts;
    bit<32> min_length;
    bit<32> max_length;
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> src_ip;
    bit<32> dst_ip;
}

struct flow_state_t {
    bit<64> packet_count;
    bit<64> byte_count;
    bit<64> last_ts;
    bit<32> min_length;
    bit<32> max_length;
}

register<flow_state_t>(1024) flow_state;

struct headers_t {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    telemetry_t  telemetry;
}

struct parser_metadata_t {
    bit<8>  protocol_id;
    bit<32> slot;
}

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
        /* Compute slot from the same 5-tuple hash used in Stage 2. */
        bit<32> h = hdr.ipv4.srcAddr ^ hdr.ipv4.dstAddr;
        meta.slot = h & 1023;
        transition accept;
    }
}

control IngressImpl(inout headers_t hdr,
                    inout parser_metadata_t meta,
                    inout standard_metadata_t std_meta)
{
    apply {
        flow_state_t s = flow_state.read(meta.slot);
        hdr.telemetry.setValid();
        hdr.telemetry.protocol_id  = meta.protocol_id;
        hdr.telemetry.packet_count = s.packet_count;
        hdr.telemetry.byte_count   = s.byte_count;
        hdr.telemetry.last_ts      = s.last_ts;
        hdr.telemetry.min_length   = s.min_length;
        hdr.telemetry.max_length   = s.max_length;
        hdr.telemetry.src_ip       = hdr.ipv4.srcAddr;
        hdr.telemetry.dst_ip       = hdr.ipv4.dstAddr;

        /* Emit only on the telemetry port; never on the data path. */
        std_meta.egress_spec = TELEMETRY_PORT;
    }
}

control EgressImpl(inout headers_t hdr,
                   inout parser_metadata_t meta,
                   inout standard_metadata_t std_meta)
{
    apply {}
}

control VerifyChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) { apply {} }
control ComputeChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) { apply {} }

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.telemetry);
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
