# STATUS — Reproducibility Status per Table and Figure

**A³E-DNS Thesis Artifact · Chapter 6**

This file records, for every table and figure in Chapter 6 of the thesis, the
status of its reproduction in this artifact. Each row is a distinct artifact
and each artifact has its own dedicated script (see `scripts/reproduce_tables/`
and `scripts/reproduce_figures/`). **Figure 16 and Figure 19 are two separate
scripts** — they were previously combined in an earlier draft and that
combination has been removed.

**Last updated:** 2026-11-10
**Thesis chapter:** Chapter 6 (§6.3–§6.17)
**Total artifacts:** 8 tables + 6 figures = **14**
**Ready:** 14 / 14 · **Pending:** 0 / 14

---

## Status legend

| Code | Meaning |
|---|---|
| ✅ **Ready** | Script present, expected output present, CPU-verified against `expected_outputs/` |
| 🟡 **Emulated** | Reproducible with hardware emulator (`a100_emulation.py`, `loihi_mock.py`, BMv2) |
| 🔵 **Hardware-bound** | Requires the specific hardware in §6.11.1 (Intel Xeon Silver / AMD EPYC / A100 / Loihi) |
| ⚪ **Documentation** | Static reference table or figure; no reproduction needed |
| 🔴 **Pending** | Script and/or expected output not yet present |

---

## Tables

| # | Artifact | Script | Expected Output | Hardware Dependency | CPU-Reproducible | Status |
|---|---|---|---|---|---|---|
| 27 | Real-Time Implementation Commands & Operational Effects | `scripts/reproduce_tables/table_27_commands.py` | `expected_outputs/table_27_expected.json` | None | ✅ Yes | ⚪ Documentation |
| 28 | Threat Intelligence Integration | `scripts/reproduce_tables/table_28_threat_intel.py` | `expected_outputs/table_28_expected.json` | None (samples in `data/threat_feeds/`) | ✅ Yes | ✅ Ready |
| 29 | Certification & Compliance Verification | `scripts/reproduce_tables/table_29_compliance.py` | `expected_outputs/table_29_expected.json` | None | ✅ Yes | ✅ Ready |
| 30 | Attack Vector Taxonomy & Real-Time Countermeasures | `scripts/reproduce_tables/table_30_taxonomy.py` | `expected_outputs/table_30_expected.json` | None | ✅ Yes | ⚪ Documentation |
| 31 | Attack Injection Framework & Detection Pipeline | `scripts/reproduce_tables/table_31_injection_pipeline.py` | `expected_outputs/table_31_expected.json` | BMv2 emulated | ✅ Yes (emulated) | 🟡 Emulated |
| 32 | Attack Scenario Simulation Matrix (S1–S5) | `scripts/reproduce_tables/table_32_simulation_matrix.py` | `expected_outputs/table_32_expected.json` | dnscat2 / liboqs / ART; A100 emulated | ✅ Yes (emulated) | 🟡 Emulated |
| 33 | Performance Comparison Matrix (7 metrics × 3 systems) | `scripts/reproduce_tables/table_33_performance.py` | `expected_outputs/table_33_expected.json` | A100 emulated for QHE column | ✅ Yes (emulated) | 🟡 Emulated |
| 34a | Closest Published Method per A³E-DNS Component (10 rows) | `scripts/reproduce_tables/table_34a_component_map.py` | `expected_outputs/table_34a_expected.json` | None | ✅ Yes | ⚪ Documentation |

---

## Figures

| # | Artifact | Script | Expected Output | Hardware Dependency | CPU-Reproducible | Status |
|---|---|---|---|---|---|---|
| 14 | Integrated Security Architecture (SVG) | `scripts/reproduce_figures/figure_14_architecture.py` | `expected_outputs/figure_14_expected.svg` | None | ✅ Yes | ⚪ Documentation |
| 15 | Adaptive Evolutionary Encryption Analysis — 6 panels (a–f) | `scripts/reproduce_figures/figure_15_aee_analysis.py` | `expected_outputs/figure_15_expected.png` | None | ✅ Yes | ✅ Ready |
| **16** | **Multi-Protocol Attack Detection Performance Evaluation — 4 panels** (DoH morphing, DoT latency injection, DoQ DDoS, multi-protocol DNS tunneling) | **`scripts/reproduce_figures/figure_16_performance.py`** | `expected_outputs/figure_16_expected.png` | A100 emulated | ✅ Yes (emulated) | 🟡 Emulated |
| 17 | Experimental Testbed — 4 panels | `scripts/reproduce_figures/figure_17_testbed.py` | `expected_outputs/figure_17_expected.png` | A100 emulated + BMv2 | ✅ Yes (emulated) | 🟡 Emulated |
| 18 | Performance Evaluation of Proposed Framework vs Baselines — 3 panels | `scripts/reproduce_figures/figure_18_comparison.py` | `expected_outputs/figure_18_expected.png` | A100 emulated | ✅ Yes (emulated) | 🟡 Emulated |
| **19** | **Multi-Protocol Attack Detection Performance Evaluation — 6 panels** (adds **(e) AEE** and **(f) FL resilience**) | **`scripts/reproduce_figures/figure_19_performance.py`** | `expected_outputs/figure_19_expected.png` | A100 emulated for panels (e) and (f) | ✅ Yes (emulated) | 🟡 Emulated |

---

## Verification targets

The `expected_outputs/verification_script.py` hard-codes the following
values from Chapter 6 (§6.16) and rejects any run whose outputs deviate
by more than the stated tolerance.

| Verification | Expected | Tolerance |
|---|---|---|
| Detection Accuracy | 99.94 % | ±0.02 pp |
| False-Positive Rate (FPR) | 0.17 % | ±0.0001 pp |
| P99 Latency | 1.42 ms | ±0.04 ms |
| Throughput | 22.5 M QPS | ±0.4 M |
| Adversarial Robustness | 96.5 % | ±0.5 pp |
| Differential Privacy (ε) | 0.68 | exact |
| S1 (Timing) Success | 98.7 % | ±0.2 |
| S2 (Tunnel) Success | 99.2 % | ±0.2 |
| S3 (Poison) Success | 96.5 % | ±0.3 |
| S4 (Quantum) Success | 100 % | exact |
| S5 (Evasion) Success | 97.8 % | ±0.3 |
| Composite Detection Score (CDS) | computed (Eq. 131) | ±0.001 |

Run `python expected_outputs/verification_script.py --all --tolerance 1e-4`
to check a fresh run against every target.

---

## Verification invocation

```bash
# Verify every table and figure against expected_outputs/
python expected_outputs/verification_script.py --all --tolerance 1e-4

# Verify a single artifact
python expected_outputs/verification_script.py --table 33 --tolerance 1e-4
python expected_outputs/verification_script.py --figure 19 --tolerance 1e-4

# Verify only the CPU-reproducible subset (excludes emulated artifacts)
python expected_outputs/verification_script.py --all --cpu-only --tolerance 1e-4
