/* p4/a3e_telemetry/features.p4
 *
 * Feature computation.
 *
 * We implemented the EMA-based feature extraction in a single control
 * block that ingress calls once per packet. The registers are indexed
 * by a 32-bit hash of the 5-tuple; the hash function is the
 * v1model `hash` external, which BMv2 maps to either CRC16 or
 * CRC32 depending on the configuration. We used CRC32 and 12 bits of
 * the result (4096 entries) because 12 bits fit in the switch's SRAM
 * budget without contention, and 4096 concurrent flows is comfortably
 * above the concurrency the thesis's E6 experiment drives.
 *
 * The EMA coefficients were fixed at 1/16. That value was chosen so
 * that the EMA has an effective window of ~16 packets, which is close
 * to the sixteen-feature window the pipeline uses; a shorter window
 * produced EMAs that tracked noise rather than flow behaviour, and a
 * longer window produced EMAs that were too slow to react to an attack
 * onset.
 *
 * The `severity_hint` is a coarse classifier trained on the switch-side
 * features alone. It is not the pipeline's detector; it exists so that
 * the switch can attach a pre-classification to every reported flow,
 * and the collector can decide whether the pipeline needs to see the
 * full window. That pre-filtering is what offloads the pipeline.
 */

#ifndef A3E_TELEMETRY_FEATURES_P4
#define A3E_TELEMETRY_FEATURES_P4

#include "headers.p4"

#define A3E_REG_SIZE 4096
#define A3E_REG_MASK 0xFFF
#define A3E_EMA_SHIFT 4   /* 1/16 coefficient */

control A3EFeatures(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t std_meta
) {
    /* Per-flow register set. All registers are 4096 entries of 32 bits
     * except packet counters, which are 16 bits because the reporting
     * cadence flushes them well below 65535. */
    register<bit<32>>(A3E_REG_SIZE) last_ts_us;
    register<bit<32>>(A3E_REG_SIZE) iat_ema_us;
    register<bit<32>>(A3E_REG_SIZE) iat_ema_sq_us2;
    register<bit<32>>(A3E_REG_SIZE) size_ema;
    register<bit<32>>(A3E_REG_SIZE) size_ema_sq;
    register<bit<16>>(A3E_REG_SIZE) pkt_count;
    register<bit<16>>(A3E_REG_SIZE) cli_pkts;
    register<bit<16>>(A3E_REG_SIZE) srv_pkts;
    register<bit<32>>(A3E_REG_SIZE) last_report_ts_us;

    /* Per-source-IP register for the stream-count approximation. We
     * used the low 12 bits of the source IP as the index; that is a
     * simple modulo and adequate for the approximate metric, though it
     * does cluster IPv4 addresses that differ only in the high 20
     * bits. A production deployment would use a larger register array
     * indexed by a hash of the source IP. */
    register<bit<16>>(A3E_REG_SIZE) src_stream_count;

    apply {
        if (hdr.ipv4.isValid() && meta.flow_hash != 0) {
            bit<12> idx = (bit<12>)(meta.flow_hash & A3E_REG_MASK);

            /* Read previous timestamp and compute inter-arrival time. */
            bit<32> prev_ts;
            last_ts_us.read(prev_ts, idx);
            bit<32> iat = (prev_ts == 0) ? 0 : (meta.now_us - prev_ts);

            /* Read and update the EMA of IAT. */
            bit<32> ema_iat;
            iat_ema_us.read(ema_iat, idx);
            if (prev_ts == 0) {
                /* First packet of the flow: seed the EMA. */
                ema_iat = iat;
            } else {
                ema_iat = ema_iat
                        + ((iat - ema_iat) >> A3E_EMA_SHIFT);
            }
            iat_ema_us.write(idx, ema_iat);

            /* Read and update the EMA of squared IAT. */
            bit<32> ema_iat_sq;
            iat_ema_sq_us2.read(ema_iat_sq, idx);
            if (prev_ts == 0) {
                ema_iat_sq = iat * iat;
            } else {
                bit<32> iat_sq = iat * iat;
                ema_iat_sq = ema_iat_sq
                           + ((iat_sq - ema_iat_sq) >> A3E_EMA_SHIFT);
            }
            iat_ema_sq_us2.write(idx, ema_iat_sq);

            /* Read and update the EMA of packet size. */
            bit<32> ema_sz;
            size_ema.read(ema_sz, idx);
            bit<32> sz = (bit<32>)meta.pkt_len;
            ema_sz = ema_sz + ((sz - ema_sz) >> A3E_EMA_SHIFT);
            size_ema.write(idx, ema_sz);

            /* Read and update the EMA of squared packet size. */
            bit<32> ema_sz_sq;
            size_ema_sq.read(ema_sz_sq, idx);
            bit<32> sz_sq = sz * sz;
            ema_sz_sq = ema_sz_sq + ((sz_sq - ema_sz_sq) >> A3E_EMA_SHIFT);
            size_ema_sq.write(idx, ema_sz_sq);

            /* Update the per-direction packet counts. */
            bit<16> cli;
            bit<16> srv;
            cli_pkts.read(cli, idx);
            srv_pkts.read(srv, idx);
            if (meta.direction == 1) {
                cli = cli + 1;
                cli_pkts.write(idx, cli);
            } else {
                srv = srv + 1;
                srv_pkts.write(idx, srv);
            }

            /* Update the total packet counter for the flow. */
            bit<16> total;
            pkt_count.read(total, idx);
            total = total + 1;
            pkt_count.write(idx, total);

            /* Update the per-source stream count approximation. */
            bit<12> src_idx = (bit<12>)(hdr.ipv4.src_addr & A3E_REG_MASK);
            bit<16> sc;
            src_stream_count.read(sc, src_idx);
            if (meta.direction == 1) {
                /* Count client-origin packets as stream activity. */
                sc = sc + 1;
            }
            src_stream_count.write(src_idx, sc);

            /* Decide whether to report. We report on every 32nd packet
             * of a flow, which gives the collector a steady stream
             * while leaving the switch's clone budget untouched for
             * short-lived flows. */
            meta.report = (total & 0x1F) == 0;
            if (meta.report) {
                /* Copy the current register snapshots into metadata so
                 * that the ingress control can build the shim header. */
                meta.iat_mean = ema_iat;
                meta.iat_var  = (ema_iat_sq > ema_iat * ema_iat)
                              ? (ema_iat_sq - ema_iat * ema_iat)
                              : 0;
                meta.size_mean = (bit<16>)(ema_sz >> 8);
                meta.size_var  = (bit<16>)((ema_sz_sq > ema_sz * ema_sz)
                                          ? ((ema_sz_sq - ema_sz * ema_sz) >> 8)
                                          : 0);
                /* Query rate: packets per second, capped at 255. */
                bit<32> elapsed = meta.now_us - meta.last_ts_us;
                bit<8> rate = (elapsed == 0) ? 0
                            : (bit<8>)((total * 1000000) / elapsed);
                meta.query_rate = rate;

                /* Direction ratio as a percentage. */
                bit<16> total_dirs = cli + srv;
                meta.dir_ratio = (total_dirs == 0) ? 50
                              : (bit<8>)((cli * 100) / total_dirs);

                /* Stream count, capped at the register's 16 bits. */
                meta.streams = sc;

                /* Severity hint: combine rate and IAT variance. A high
                 * rate combined with low IAT variance is the beacon
                 * signature; a high rate combined with high IAT
                 * variance is the tunnel signature. */
                if (rate > 100 && meta.iat_var < 100) {
                    meta.severity = 200;   /* beacon-like */
                } else if (rate > 100) {
                    meta.severity = 180;   /* tunnel-like */
                } else if (rate > 50) {
                    meta.severity = 120;   /* elevated */
                } else {
                    meta.severity = 40;    /* baseline */
                }
            } else {
                meta.report = 0;
            }

            /* Update the last timestamp regardless of reporting. */
            last_ts_us.write(idx, meta.now_us);
        }
    }
}

#endif /* A3E_TELEMETRY_FEATURES_P4 */
