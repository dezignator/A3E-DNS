/* p4/a3e_telemetry/ingress.p4
 *
 * Ingress pipeline.
 *
 * The ingress control does four things in order:
 *
 *   1. Compute the 5-tuple hash that indexes the feature registers.
 *   2. Assign the transport class from the port pair.
 *   3. Assign the direction (client→resolver or resolver→client) from
 *      the same port pair, using the transport class.
 *   4. Run the feature computation, then build and clone the shim
 *      header if the report flag is set.
 *
 * The transport class assignment uses the standard port numbers:
 * DoH/DoQ share 443, DoT uses 853. For DoQ we checked the IP protocol
 * is UDP; for DoH it must be TCP. The assignment is done by a
 * two-entry table rather than by if-else because the BMv2 optimizer
 * handles tables more efficiently than conditionals in the pipeline
 * budget.
 */

#ifndef A3E_TELEMETRY_INGRESS_P4
#define A3E_TELEMETRY_INGRESS_P4

#include "headers.p4"

control A3EIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t std_meta
) {
    A3EFeatures() features;

    /* Transport class lookup table. */
    action set_transport_class(bit<3> cls) {
        meta.transport_class = cls;
    }
    table transport_class_tbl {
        key = {
            hdr.ipv4.protocol : exact;
            hdr.tcp.dst_port   : exact;
            hdr.udp.dst_port   : exact;
        }
        actions = { set_transport_class; NoAction; }
        default_action = NoAction();
    }

    /* Direction assignment. */
    action set_direction(bit<1> dir) {
        meta.direction = dir;
    }
    table direction_tbl {
        key = {
            meta.transport_class : exact;
            meta.ingress_port_id : ternary;
        }
        actions = { set_direction; NoAction; }
        default_action = set_direction(0);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            meta.ingress_port_id = std_meta.ingress_port;
            meta.pkt_len = hdr.ipv4.total_len;
            meta.now_us = (bit<32>)(std_meta.ingress_global_timestamp / 1000);

            /* 5-tuple hash. */
            bit<32> h;
            hash(h,
                 HashAlgorithm.crc32,
                 (bit<1>)0,
                 {
                     hdr.ipv4.src_addr,
                     hdr.ipv4.dst_addr,
                     hdr.tcp.src_port,
                     hdr.tcp.dst_port,
                     hdr.udp.src_port,
                     hdr.udp.dst_port
                 },
                 (bit<32>)0);
            meta.flow_hash = h;

            /* Classify the transport. */
            transport_class_tbl.apply();

            /* Assign the direction. */
            direction_tbl.apply();

            /* Compute features. */
            features.apply(hdr, meta, std_meta);

            /* If the feature control set the report flag, build the
             * shim and clone the packet to the collector. */
            if (meta.report == 1) {
                hdr.a3e_feature.setValid();
                hdr.a3e_feature.flow_hash         = meta.flow_hash;
                hdr.a3e_feature.last_ts_us        = meta.now_us;
                hdr.a3e_feature.iat_mean_us       = meta.iat_mean;
                hdr.a3e_feature.iat_var_us2       = meta.iat_var;
                hdr.a3e_feature.pkt_size_mean     = meta.size_mean;
                hdr.a3e_feature.pkt_size_var      = meta.size_var;
                hdr.a3e_feature.query_rate_per_s  = meta.query_rate;
                hdr.a3e_feature.direction_ratio_pct = meta.dir_ratio;
                hdr.a3e_feature.stream_count      = meta.streams;
                hdr.a3e_feature.severity_hint     = meta.severity;
                /* Clone to the collector port. The port was installed
                 * by the control plane; the constant 100 is the
                 * convention the install_rules.py script uses. */
                clone3(CloneType.I2E, 100, (bit<32>)meta.severity);
            }
        }
    }
}

#endif /* A3E_TELEMETRY_INGRESS_P4 */
