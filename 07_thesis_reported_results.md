# 07. Results reported in Chapter 6 and an arithmetic check

These are the thesis figures (Table 32, Table 33). They are **not produced by the v2 harness**. They come from the testbed of Section 6.11 and are reproduced here so that the repository contains one place where every reported number can be traced and recomputed.

## Table 33 with recomputed improvement columns

| metric | DNSGuard | DeepFingerprint | A3E-DNS | recomputed vs DNSGuard | recomputed vs DeepFingerprint |
|---|---|---|---|---|---|
| Detection accuracy | 91.2 | 96.7 | 99.94 | +8.74 pp | +3.24 pp |
| False-positive rate (%) | 2.1 | 0.8 | 0.17 | 12.35x lower | 4.71x lower |
| P99 latency (ms) | 4.2 | 2.8 | 1.42 | 2.96x lower | 1.97x lower |
| Throughput (M QPS) | 8 | 15 | 22.5 | 2.81x higher | 1.50x higher |
| Adversarial robustness (%) | 65 | 82 | 96.5 | +31.50 pp | +14.50 pp |

All recomputed values equal the improvement column printed in Table 33 (8.74 pp / 3.24 pp, 12.35x / 4.71x, 2.96x / 1.97x, 2.81x / 1.50x, 31.5 pp / 14.5 pp).

Other reported quantities: P99 95 % CI [1.38, 1.46] ms; throughput efficiency 0.92; adversarial gap 0.035 (= 1 - 0.965); Cohen's d = 1.87 for the FPR comparison; t-test p < 0.0001 for accuracy; epsilon = 0.68; estimated security parameter lambda = 256 (conjectured, lattice-based).

## Table 32 per scenario

| scenario | response time | success | FNR | success + FNR |
|---|---|---|---|---|
| S1-Timing | 0.4 ms | 98.7 % | 1.3 % | 100.0 % |
| S2-Tunnel | 1.2 ms | 99.2 % | 0.8 % | 100.0 % |
| S3-Poison | 2.5 ms | 96.5 % | 3.5 % | 100.0 % |
| S4-Quantum | 1.8 ms | 100 % | 0.0 % | 100.0 % |
| S5-Evasion | 0.9 ms | 97.8 % | 2.2 % | 100.0 % |

Each row is internally consistent: success and FNR add to 100 %.

## How the v2 harness relates to these numbers

The harness in `experiments_v2/` runs on a synthetic generator whose attack classes overlap by design. Its absolute numbers (for example detection F1 about 0.9) are lower than the thesis values and are not tuned to match them. The harness is intended to reproduce *directions of effect* (robust aggregation under malicious clients, the privacy/utility trade-off, the noise budget of the QHE parameters, the privacy/latency trade-off of timing jitter) and to give the testbed runs an executable specification. The testbed numbers above remain the only measured values for Chapter 6.
