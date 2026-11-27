/* p4/a3e_telemetry/headers.p4
 *
 * Header definitions for the A3E-DNS switch telemetry pipeline.
 *
 * We chose a subset of the sixteen A3E features that a PISA switch
 * can actually compute at line rate. The switch extracts:
 *
 *   - iat_mean_us    (exponential moving average of inter-arrival time),
 *   - iat_var_us2    (EMA of squared inter-arrival time, for variance),
 *   - pkt_size_mean  (EMA of packet size),
 *   - pkt_size_var   (EMA of squared packet size),
 *   - query_rate_per_s (approximate rate from a packet-count register),
 *   - direction_ratio_pct (client/server packet ratio),
 *   - stream_count   (approximate distinct-flow count per source),
 *   - severity_hint  (a coarse heuristic from protocol and port).
 *
 * The remaining eight features (qname_entropy_bits, subdomain_len_mean,
 * unique_name_ratio, payload_entropy_bits, handshake_ms,
 * proto_anomaly_score, response_size_mean, ttl_mean_s) require L7
 * visibility or state that the switch does not have, and were
 * computed by the pipeline as before. That split is the point of the
 * P4 component: offload what the switch can see, leave the rest to the
 * pipeline.
 *
 * The custom shim header (`a3e_feature_t`) is prepended to a clone of
 * the packet that is sent to the collector. We did not use the
 * standard INT-MD header because that header is designed for
 * hop-by-hop path tracing with variable-length stack entries, and our
 * use case is a single-collector delivery of a fixed-size struct. A
 * custom shim is 34 bytes versus ~80 bytes for INT-MD, and the smaller
 * shim matters because the collector receives one clone per reported
 * flow.
 */

#ifndef A3E_TELEMETRY_HEADERS_P4
#define A3E_TELEMETRY_HEADERS_P4

/* Standard headers. */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  reserved;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/* Custom A3E feature shim. */
header a3e_feature_t {
    bit<32> flow_hash;
    bit<32> last_ts_us;
    bit<32> iat_mean_us;
    bit<32> iat_var_us2;
    bit<16> pkt_size_mean;
    bit<16> pkt_size_var;
    bit<8>  query_rate_per_s;
    bit<8>  direction_ratio_pct;
    bit<16> stream_count;
    bit<8>  severity_hint;
}

struct headers_t {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    tcp_t         tcp;
    udp_t         udp;
    a3e_feature_t a3e_feature;
}

struct metadata_t {
    /* A 32-bit hash of the 5-tuple. */
    bit<32> flow_hash;
    /* Snapshot of ingress_global_timestamp. */
    bit<32> now_us;
    /* The port the packet arrived on, in the standard v1model port range. */
    bit<9>  ingress_port_id;
    /* Whether we classified the flow as DoH, DoT, DoQ, or unknown. */
    bit<3>  transport_class;
    /* Bytes of the current packet. */
    bit<16> pkt_len;
    /* Client-to-server (1) or server-to-client (0). */
    bit<1>  direction;
    /* Whether the packet should be cloned to the collector. */
    bit<1>  report;
    /* Register snapshot for the shim. */
    bit<32> iat_mean;
    bit<32> iat_var;
    bit<16> size_mean;
    bit<16> size_var;
    bit<8>  query_rate;
    bit<8>  dir_ratio;
    bit<16> streams;
    bit<8>  severity;
}

#endif /* A3E_TELEMETRY_HEADERS_P4 */
