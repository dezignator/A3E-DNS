# expected_outputs

Reference outputs for every table and figure in Chapter 6 of the thesis.
The `verification_script.py` compares a fresh run against these files;
`MANIFEST.sha256` records their integrity hashes.

**Important:** the JSON/SVG/PNG files in this directory are
**thesis-aligned reference artifacts**. They record the values that
`verification_script.py` checks against — not the values the artifact
may produce when run on different hardware. Absolute numbers on real
A100 / Loihi / P4 hardware will differ; see
`docs/HARDWARE_EMULATION.md` and `REPRODUCIBILITY_CHECKLIST.md`.

---

## Contents

| File | Source (Chapter 6) | Format | Produced by |
|---|---|---|---|
| `table_27_expected.json` | §6.x Table 27 — implementation commands | JSON | `scripts/reproduce_tables/table_27_commands.py` |
| `table_28_expected.json` | §6.7 Table 28 — threat intel | JSON | `scripts/reproduce_tables/table_28_threat_intel.py` |
| `table_29_expected.json` | §6.9 Table 29 — compliance | JSON | `scripts/reproduce_tables/table_29_compliance.py` |
| `table_30_expected.json` | §6.15 Table 30 — taxonomy | JSON | `scripts/reproduce_tables/table_30_taxonomy.py` |
| `table_31_expected.json` | §6.15 Table 31 — injection pipeline | JSON | `scripts/reproduce_tables/table_31_injection_pipeline.py` |
| `table_32_expected.json` | §6.16 Table 32 — simulation matrix (S1–S5) | JSON | `scripts/reproduce_tables/table_32_simulation_matrix.py` |
| `table_33_expected.json` | §6.16 Table 33 — performance matrix | JSON | `scripts/reproduce_tables/table_33_performance.py` |
| `table_34a_expected.json` | §6.16 Table 34a — component map | JSON | `scripts/reproduce_tables/table_34a_component_map.py` |
| `figure_14_expected.svg` | §6.3 architecture diagram | SVG | `scripts/reproduce_figures/figure_14_architecture.py` |
| `figure_15_expected.png` | §6.4 AEE analysis (6 panels) | PNG | `scripts/reproduce_figures/figure_15_aee_analysis.py` |
| `figure_16_expected.png` | §6.16 detection performance (4 panels) | PNG | `scripts/reproduce_figures/figure_16_performance.py` |
| `figure_17_expected.png` | §6.11 testbed (4 panels) | PNG | `scripts/reproduce_figures/figure_17_testbed.py` |
| `figure_18_expected.png` | §6.16 comparison (3 panels) | PNG | `scripts/reproduce_figures/figure_18_comparison.py` |
| `figure_19_expected.png` | §6.16 performance (6 panels) | PNG | `scripts/reproduce_figures/figure_19_performance.py` |
| `MANIFEST.sha256` | SHA-256 hashes of every file above | text | see below |

> **Figure 16 and Figure 19 are two separate artifacts.** Figure 16 has
> four panels; Figure 19 has six. They were combined in an earlier draft
> and that combination has been removed.

---

## Verification targets

`verification_script.py` enforces the following numeric targets (Chapter
6 §6.16). The tolerances are the ones documented in the thesis and used
by the CI:

| Verification | Expected | Tolerance | Source |
|---|---|---|---|
| Detection Accuracy | 99.94 % | ±0.02 pp | Table 33 |
| False-Positive Rate (FPR) | 0.17 % | ±0.0001 pp | Table 33 |
| P99 Latency | 1.42 ms | ±0.04 ms | Table 33 |
| Throughput | 22.5 M QPS | ±0.4 M | Table 33 |
| Adversarial Robustness | 96.5 % | ±0.5 pp | Table 33 |
| Differential Privacy (ε) | 0.68 | exact | §6.6.5 |
| S1 (Timing) Success | 98.7 % | ±0.2 | Table 32 |
| S2 (Tunnel) Success | 99.2 % | ±0.2 | Table 32 |
| S3 (Poison) Success | 96.5 % | ±0.3 | Table 32 |
| S4 (Quantum) Success | 100 % | exact | Table 32 |
| S5 (Evasion) Success | 97.8 % | ±0.3 | Table 32 |
| Composite Detection Score (CDS) | computed (Eq. 131) | ±0.001 | §6.9.1 |

---

## How to verify

```bash
# Every table and figure, CPU-reproducible subset only
python expected_outputs/verification_script.py --all --cpu-only --tolerance 1e-4

# Every table and figure, including emulated (A100/P4) artifacts
python expected_outputs/verification_script.py --all --tolerance 1e-4

# Single table
python expected_outputs/verification_script.py --table 33 --tolerance 1e-4

# Single figure
python expected_outputs/verification_script.py --figure 19 --tolerance 1e-4
