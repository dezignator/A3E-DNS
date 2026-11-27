/* p4/a3e_telemetry/parser.p4
 *
 * Parsers for the transports A3E covers.
 *
 * The parsers are deliberately shallow. A DoH flow carries TLS records
 * and, inside them, HTTP/2 frames, but the switch cannot see past the
 * TLS layer; parsing deeper than the TLS record header would have
 * produced nothing. We parsed Ethernet, IPv4, TCP or UDP, and stopped.
 * The transport class (DoH / DoT / DoQ / unknown) is assigned in
 * ingress based on ports.
 *
 * Fragmented IPv4 packets (frag_offset != 0 or MF set) are treated as
 * opaque: they have no transport header to parse and their sizes are
 * not representative of the flow's packet-size distribution, so they
 * were skipped in feature computation entirely. The metadata carries
 * the fragment flag so that ingress can decide.
 */

#ifndef A3E_TELEMETRY_PARSER_P4
#define A3E_TELEMETRY_PARSER_P4

#include "headers.p4"

parser A3EParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t std_meta
) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6:    parse_tcp;
            17:   parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

#endif /* A3E_TELEMETRY_PARSER_P4 */
