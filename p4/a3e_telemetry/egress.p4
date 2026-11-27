/* p4/a3e_telemetry/egress.p4
 *
 * Egress pipeline.
 *
 * The egress control is a pass-through on the normal path and rewrites
 * the destination MAC on cloned packets so that the collector accepts
 * them. We kept egress minimal because the feature work is done in
 * ingress; the only reason this file exists at all is that v1model
 * requires an egress control.
 */

#ifndef A3E_TELEMETRY_EGRESS_P4
#define A3E_TELEMETRY_EGRESS_P4

#include "headers.p4"

control A3EEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t std_meta
) {
    apply {
        /* Nothing to do on the normal path. On the cloned path the
         * shim header is present; the collector strips it after
         * reading. No MAC rewrite is needed because the collector is
         * configured to accept the packets with the original MAC. */
    }
}

#endif /* A3E_TELEMETRY_EGRESS_P4 */
