# A3E-DNS switch telemetry pipeline

P4_16 program for the v1model architecture that extracts a subset of
the A3E-DNS feature window at line rate and forwards the extracted
features to a collector. The pipeline consumes those features alongside
its own L7 measurements, offloading the eight features that a switch
can compute from the eight that require host-side parsing.

## What the switch extracts

| Feature | Computation |
|---------|-------------|
| `iat_mean_us` | EMA (1/16 coefficient) of inter-arrival time per flow |
| `iat_var_us2` | EMA of squared IAT minus squared EMA of IAT |
| `pkt_size_mean` | EMA of packet length |
| `pkt_size_var` | EMA of squared length minus squared EMA |
| `query_rate_per_s` | Packet count over elapsed time, capped at 255 |
| `direction_ratio_pct` | Client-origin packets as a percentage of the flow |
| `stream_count` | Per-source-IP activity counter |
| `severity_hint` | Coarse heuristic from rate and IAT variance |

## What the switch does not extract

The remaining eight features require L7 visibility or state the switch
does not have:

- `qname_entropy_bits`, `subdomain_len_mean`, `unique_name_ratio` —
  require parsing the DNS question, which is inside the TLS payload.
- `payload_entropy_bits` — same reason.
- `handshake_ms` — requires tracking handshake completion, which the
  switch can only approximate from packet counts.
- `proto_anomaly_score` — requires cross-layer correlation.
- `response_size_mean` — requires correlating request and response,
  which is state-heavy.
- `ttl_mean_s` — requires parsing the DNS response body.

Those eight are still measured by the pipeline. The switch's
contribution is that the pipeline no longer needs to measure the other
eight, which halves its per-window L7 parsing work.

## Building

```bash
p4c --target bmv2 --arch v1model \
    --p4runtime-files build/a3e_telemetry.p4info.txt \
    a3e_telemetry/main.p4
