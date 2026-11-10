/* ============================================================
 * A3E-DNS — P4 Stage 1: Parser
 * Thesis §6.12.1
 * ============================================================
 *
 * Responsibilities (§6.12.1):
 *   - transport-layer header decode
 *   - application-layer header decode
 *   - encrypted-DNS protocol identification (DoH, DoT, DoQ)
 *
 * The parser classifies the packet by port and transport, matching
 * the capture policy in ebpf_capture.c:
 *
 *   tcp port 443      -> DoH
 *   tcp port 853      -> DoT
 *   udp port 853      -> DoQ
 *
 * The parser does NOT decrypt. Payload bytes are never inspected beyond
 * the transport/application header boundary; the parser only needs the
 * ports and the transport. This matches the thesis's rule that the
 * pipeline sees only metadata (§6.3.3).
 *
 * Compile with:
 *   p4c --target bmv2 --arch v1model --std p4-16 parser.p4
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* Protocol identifiers assigned by the parser. */
const bit<8> PROTO_UNKNOWN = 0;
const bit<8> PROTO_DOH     = 1;
const bit<8> PROTO_DOT     = 2;
const bit<8> PROTO_DOQ     = 3;

/* Ports captured per §6.12.1 / §6.11.2. */
const bit<16> PORT_DOH = 443;
const bit<16> PORT_DOT = 853;
const bit<16> PORT_DOQ = 853;

/* Header emitted by the parser for downstream stages. */
header parsed_meta_t {
    bit<8>  protocol_id;        /* PROTO_* */
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  ip_proto;           /* 6 = TCP, 17 = UDP */
    bit<32> src_ip;
    bit<32> dst_ip;
}

struct parser_metadata_t {
    parsed_meta_t parsed;
}

struct headers_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    parsed_meta_t   parsed;
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
        transition select(hdr.ipv4.protocol) {
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        /* Only the first 4 bytes of the TCP header carry the ports we
         * need; the remainder is skipped. */
        bit<16> sport;
        bit<16> dport;
        packet.extract(sport);
        packet.extract(dport);
        /* Protocol identification by port. */
        bit<8> proto = PROTO_UNKNOWN;
        if (sport == PORT_DOH || dport == PORT_DOH) {
            proto = PROTO_DOH;
        } else if (sport == PORT_DOT || dport == PORT_DOT) {
            proto = PROTO_DOT;
        }
        hdr.parsed.setValid();
        hdr.parsed.protocol_id = proto;
        hdr.parsed.src_port    = sport;
        hdr.parsed.dst_port    = dport;
        hdr.parsed.ip_proto    = 6;
        hdr.parsed.src_ip      = hdr.ipv4.srcAddr;
        hdr.parsed.dst_ip      = hdr.ipv4.dstAddr;
        meta.parsed = hdr.parsed;
        transition accept;
    }

    state parse_udp {
        bit<16> sport;
        bit<16> dport;
        packet.extract(sport);
        packet.extract(dport);
        bit<8> proto = PROTO_UNKNOWN;
        if (sport == PORT_DOQ || dport == PORT_DOQ) {
            proto = PROTO_DOQ;
        }
        hdr.parsed.setValid();
        hdr.parsed.protocol_id = proto;
        hdr.parsed.src_port    = sport;
        hdr.parsed.dst_port    = dport;
        hdr.parsed.ip_proto    = 17;
        hdr.parsed.src_ip      = hdr.ipv4.srcAddr;
        hdr.parsed.dst_ip      = hdr.ipv4.dstAddr;
        meta.parsed = hdr.parsed;
        transition accept;
    }
}

/* Ingress / egress pipelines are no-ops; Stage 2 (match_action.p4)
 * does the per-flow statistics, and Stage 3 (metadata_gen.p4) does
 * the telemetry emission. */
control IngressImpl(inout headers_t hdr,
                    inout parser_metadata_t meta,
                    inout standard_metadata_t std_meta)
{
    apply {
        /* No ingress action in the parser stage. */
    }
}

control EgressImpl(inout headers_t hdr,
                   inout parser_metadata_t meta,
                   inout standard_metadata_t std_meta)
{
    apply {}
}

control VerifyChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) {
    apply {}
}

control ComputeChecksumImpl(inout headers_t hdr, inout parser_metadata_t meta) {
    apply {}
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
