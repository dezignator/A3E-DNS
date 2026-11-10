# data/

Datasets, fixtures, and generators for the A3E-DNS thesis artifact.

**Every downloaded dataset is gitignored** (see `.gitignore`). Only the
small fixtures and the generators are committed. The full data set is
obtained via `data/download_datasets.py --mode full`.

---

## Contents

| File / directory | Committed | Purpose | Reference |
|---|---|---|---|
| `README.md` | ✅ | this file | — |
| `MANIFEST.sha256` | ✅ | hashes for downloaded + synthetic data | §7.3.4 |
| `attack_matrix.json` | ✅ | S1–S5 + 6-vector taxonomy | Table 30, Table 32 |
| `attack_taxonomy.json` | ✅ | 6 attack classes | Table 30 |
| `compliance_mapping.json` | ✅ | 5 standards | Table 29 |
| `threat_feeds/` | ✅ | 4 fixture files (STIX, honeypot, darknet, vendor) | §6.7, Table 28 |
| `synthetic/` | ✅ | small `.npz` samples (toy-sized) | §6.13 |
| `data_utils.py` | ✅ | shared helpers | §6.13 |
| `download_datasets.py` | ✅ | fetch DS-1/2/3 + verify SHA-256 | §7.3.4 |
| `preprocess_zenodo.py` | ✅ | DS-1 (32 GB) Dask preprocessing | §6.13 |
| `preprocess_doh_realworld.py` | ✅ | DS-2 preprocessing | §6.13 |
| `preprocess_kosekmi_doq.py` | ✅ | DS-3 preprocessing | §6.13 |
| `generate_synthetic.py` | ✅ | regenerate `synthetic/*.npz` | §6.13 |
| `raw/`, `zenodo/`, `doh_realworld/`, `kosekmi_doq/` | ❌ gitignored | downloaded data | §6.11.2 |

---

## The four dataset groups

| ID | Dataset | Size | Source | Used by |
|---|---|---|---|---|
| **DS-1** | Zenodo 5957677 | 32 GB | https://doi.org/10.5281/zenodo.5957677 | Tables 31–33, Figures 16–19 |
| **DS-2** | DoH Real-World 2022 | ~5 GB | `download_datasets.py --dataset doh_realworld` | Tables 32–33 |
| **DS-3** | Kosekmi 2022 (DoQ) | ~2 GB | `download_datasets.py --dataset kosekmi_doq` | Tables 32–33 |
| **TI-1** | Synthetic attacks + threat intel | < 10 MB | `generate_synthetic.py` | Table 28, Table 31 |

Full provenance is in `docs/DATA_PROVENANCE.md`.

---

## Downloading

```bash
# Toy mode — no external downloads (schema-matched synthetic only)
python data/download_datasets.py --mode toy

# Full mode — download DS-1, DS-2, DS-3 (≈ 39 GB)
python data/download_datasets.py --mode full --verify-sha256
