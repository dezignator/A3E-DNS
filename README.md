# A³E-DNS

**Next-Generation Secure and Adaptive Evolutionary Encryption for DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC**

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Status: Thesis Artifact](https://img.shields.io/badge/Status-Thesis%20Artifact-green.svg)]()
[![Reproducibility: CPU + Emulated GPU](https://img.shields.io/badge/Reproducibility-CPU%20%2B%20Emulated%20GPU-orange.svg)](./REPRODUCIBILITY_CHECKLIST.md)
[![Thesis Alignment: Chapter 6](https://img.shields.io/badge/Thesis%20Alignment-Chapter%206-purple.svg)]()

---

## Abstract

**A³E-DNS** is the integrated, industry-deployable reference artifact for the A³E-DNS framework presented in **Chapter 6** of the thesis *"Next-Generation Secure Encrypted DNS Architectures: Four Complementary Frameworks for Adaptive, Privacy-Preserving, and Quantum-Resilient Defense."*

The framework combines three previously disjoint strands:

1. **Adaptive Evolutionary Encryption (AEE)** — SE(3)ⁿ-Lie-group-driven key evolution keyed on traffic entropy and hardware entropy (`RDRAND`/`RDSEED`).
2. **Optimized Quantum-Safe Homomorphic Encryption (QHE)** — Ring-LWE with NTT + AVX-512 + Ziggurat sampling + selective homomorphic operations (parameters `n = 256`, `q = 4096` per §6.5; see [LIMITATIONS.md](./docs/LIMITATIONS.md) for the documented Table-27 inconsistency).
3. **AI-Augmented Federated Learning (FL)** — spatio-temporal attention (8 layers × 12 heads), temporal decay, min-max PGD adversarial training, and geometric-median Byzantine-robust aggregation.

On the containerized 4-node testbed specified in §6.11.1, the integrated framework reaches **99.94 % detection accuracy**, **0.17 % false-positive rate**, **1.42 ms P99 latency**, **22.5 M QPS** throughput, **96.5 % adversarial robustness**, and a **differential-privacy budget of ε = 0.68**. Post-quantum resistance is conjectured under Module-LWE (AEE key encapsulation) and Ring-LWE (QHE layer), not proven.

> **No new cryptographic primitive is proposed.** Every cryptographic component is an existing, standardized, or published scheme. A full factorial ablation of the integration was **not** performed (§7.3.1).

---

## Key Results (Table 33 — 7 metrics × 3 systems)

| Metric | DNSGuard | DeepFingerprint | **Proposed (A³E-DNS)** | Improvement (vs DNSGuard; vs DeepFingerprint) | Statistical note |
|---|---|---|---|---|---|
| Detection Accuracy | 91.2 % | 96.7 % | **99.94 %** | +8.74 pp; +3.24 pp | *t*-test, *p* < 0.0001 |
| False-Positive Rate | 2.1 % | 0.8 % | **0.17 %** | 12.35× lower; 4.71× lower | Cohen's *d* = 1.87 |
| P99 Latency | 4.2 ms | 2.8 ms | **1.42 ms** | 2.96× lower; 1.97× lower | 95 % CI [1.38, 1.46] ms |
| Throughput | 8 M QPS | 15 M QPS | **22.5 M QPS** | 2.81× higher; 1.50× higher | Throughput efficiency 0.92 |
| Adversarial Robustness | 65 % | 82 % | **96.5 %** | +31.5 pp; +14.5 pp | Adversarial gap 0.035 (§6.16.3) |
| Privacy Leakage (ε) | n/a | n/a | **0.68** | not comparable as a ratio (see notes) | DP mechanism at ε = 0.68 (§6.6.5) |
| Quantum Resistance | none | partial (hybrid) | **lattice-based (conjecture)** | categorical difference; no ratio computed | Module-LWE + Ring-LWE (§6.9.2) |

**Notes.** Percentage-point (pp) differences are used for accuracy, robustness, and any bounded rate. Ratio improvements are used only where both systems measure the same quantity on the same scale (latency, throughput, FPR). `ε` is a bound on the privacy loss of a *specific mechanism under a specific neighbourhood relation* — a ratio between two `ε` values from different mechanisms is not informative and is **not** reported. Quantum resistance is reported as a **capability category**, not a numerical factor. Baseline figures are from reproduced/retrained runs on the same data, same preprocessing, and same tuning budget (§6.16.2). Per-class sample counts, number of runs, split, tuning procedure and random seeds are recorded in `expected_outputs/MANIFEST.sha256` and `docs/REPRODUCIBILITY.md`.

---

## Repository Structure
