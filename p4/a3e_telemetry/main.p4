/* p4/a3e_telemetry/main.p4
 *
 * Package for the v1model architecture. This is the file p4c
 * compiles; the others are included.

#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "features.p4"
#include "ingress.p4"
#include "egress.p4"

control A3EDeparser(
    packet_out pkt,
    inout headers_t hdr
) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.a3e_feature);
    }
}

control A3EVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply { }
}

control A3EComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply { }
}

V1Switch(
    A3EParser(),
    A3EVerifyChecksum(),
    A3EIngress(),
    A3EEgress(),
    A3EComputeChecksum(),
    A3EDeparser()
) main;
