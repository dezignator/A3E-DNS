
---

### File 5 — `REPRODUCIBILITY_CHECKLIST.md`

**Upload path on GitHub:** repository root, exact filename `REPRODUCIBILITY_CHECKLIST.md`

```markdown
# REPRODUCIBILITY CHECKLIST

**A³E-DNS Thesis Artifact · Chapter 6**

This checklist distinguishes artifacts that are **fully CPU-reproducible**
(no special hardware, no external data download) from those that require
**hardware emulation** or **external datasets**. Every artifact is tagged
with one of four tiers; every tier has a defined verification command.

---

## Tier definitions

| Tier | Label | What it requires |
|---|---|---|
| **A** | **CPU-reproducible** | Runs end-to-end on a stock 16-core x86-64 CPU with no GPUs, no special hardware, and only the toy datasets shipped in `data/synthetic/`. |
| **B** | **Hardware-emulated** | Requires the emulators in `src/hardware_simulation/` (`a100_emulation.py`, `loihi_mock.py`, BMv2). Runs on CPU; absolute numbers differ from real hardware but trends are preserved. |
| **C** | **Hardware-bound** | Requires the real hardware in §6.11.1 (A100 / Loihi / P4 switch) to reproduce the reported absolute figures. Emulation gives the trends, not the raw values. |
| **D** | **Data-dependent** | Requires the full external datasets (Zenodo DS-1 32 GB, DoH-RealWorld DS-2, Kosekmi-2022 DS-3). Not reproducible without those downloads. |

Every artifact carries exactly **one** of these tags. Artifacts that mix
tiers (e.g. one panel CPU-only, another panel hardware-emulated) are
split into per-panel sub-tiers in the tables below.

---

## Tier A — Fully CPU-reproducible

**Runtime:** ~2 min in toy mode · **Hardware:** any 16-core x86-64 CPU

| Artifact | Command | Expected output |
|---|---|---|
| Table 28 — Threat Intel | `python scripts/reproduce_tables/table_28_threat_intel.py --mode toy` | `expected_outputs/table_28_expected.json` |
| Table 29 — Compliance | `python scripts/reproduce_tables/table_29_compliance.py --mode toy` | `expected_outputs/table_29_expected.json` |
| Figure 14 — Architecture SVG | `python scripts/reproduce_figures/figure_14_architecture.py --mode toy` | `expected_outputs/figure_14_expected.svg` |
| Figure 15 — AEE analysis (6 panels) | `python scripts/reproduce_figures/figure_15_aee_analysis.py --mode toy` | `expected_outputs/figure_15_expected.png` |

**Verification:**
```bash
python expected_outputs/verification_script.py --all --tier A --tolerance 1e-4
