# A3E-DNS v2 (extended reference implementation and evaluation package)

This package extends the reproducibility artifact of Chapter 6, *Integrated Next-Generation Secure DNS Architecture (A3E-DNS)*, which combines Adaptive Evolutionary Encryption (AEE), Quantum-Safe Homomorphic Encryption (QHE) and AI-Augmented Federated Learning (AFL) across DoH, DoT and DoQ. Version 1 holds the scripts and configuration of the chapter. Version 2 adds, in separate files and folders so that nothing in version 1 is overwritten:

- a full Python implementation of each mechanism (`src/a3e_dns_v2/`) with 42 unit tests,
- ten experiments that write tables and figures (`experiments_v2/`, `results_v2/`),
- an attack catalogue with 13 scenarios and 51 cases, a threat model, and an evaluation protocol (`docs/v2/`),
- deployment artifacts for the data plane and the testbed (`deployment/v2/`),
- an interactive HTML dashboard (`dashboards/a3e_v2_dashboard.html`),
- an audit of the parameters and equations of Chapter 6 (`docs/v2/08_consistency_audit.md`).

## Two kinds of numbers

| kind | where | origin |
|---|---|---|
| reported in the thesis | `docs/v2/07_thesis_reported_results.md`, dashboard tab "Thesis results" | testbed of Section 6.11 |
| harness results | `results_v2/`, `docs/v2/09_harness_results.md`, other dashboard tabs | synthetic traffic generator, produced by the code in this package |

Harness results carry a banner and are never merged with thesis results. They are lower than the thesis values by design: the synthetic attack classes overlap, and we did not tune the generator toward the reported figures. The harness shows the direction and size of effects (for example robust aggregation under malicious clients, the privacy and utility trade-off, the QHE noise budget) and defines executable specifications for the testbed runs.

## Layout

```
README_V2.md  CHANGELOG_V2.md  Makefile.v2  requirements-v2.txt  MANIFEST_V2.sha256
src/a3e_dns_v2/        aee/  qhe/  fl/  intel/  sandbox/  traffic.py  metrics.py  pipeline.py  params.py  torch_detector_v2.py
experiments_v2/        e1 to e10, run_all.py, fl_coordinator_v2.py, qhe_analyzer_v2.py, common.py
tests_v2/              test_core.py (42 tests)
configs/v2/            default, ablation matrix, scenarios, FL and DP grids, dataset columns, testbed nodes
deployment/v2/         ebpf/ (XDP), p4/ (BMv2), scripts/ (Mininet, netem, Dask), docker-compose.v2.yml
docs/v2/               01 traceability ... 10 limitations
results_v2/            tables/ (CSV + Markdown), figures/ (PNG), run_metadata.json
dashboards/            a3e_v2_dashboard.html (self-contained)
notebooks_v2/          a3e_v2_walkthrough.ipynb
data/v2/               parameter registry CSV, synthetic flow sample
tools_v2/              build_docs.py, build_results_report.py, build_dashboard.py
```

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-v2.txt
make -f Makefile.v2 test        # 42 unit tests
make -f Makefile.v2 results     # all experiments, about 3 minutes on one core
python3 tools_v2/build_docs.py && python3 tools_v2/build_results_report.py && python3 tools_v2/build_dashboard.py
```

Open `dashboards/a3e_v2_dashboard.html` in a browser; it needs no server.

## Mapping to Chapter 6

`docs/v2/01_chapter6_traceability.md` lists every section, the file that implements it and its status (implemented, partial, not reproduced).

## Experiments

| id | topic | Chapter 6 |
|---|---|---|
| E1 | detection by scenario and protocol, severity sweep | 6.15, 6.16 |
| E2 | Byzantine sweep over five aggregators and four attacks | 6.6.4 |
| E3 | differential privacy sweep and noise calibration grid | 6.6.5 |
| E4 | homomorphic layer: noise growth, samplers, NTT, encrypted histograms, selective operations | 6.5 |
| E5 | adaptive encryption: SE(3), key stream screening, controller cost, timing side channel | 6.4 |
| E6 | 2^3 factorial ablation | 6.17 |
| E7 | sandbox policy and rollouts | 6.3.2, 6.14.3 |
| E8 | threat-intelligence fusion and darknet scans | 6.7 |
| E9 | PGD robustness and blending evasion | 6.6.3 |
| E10 | attack-case matrix | 6.15 |

## Limits

- Cryptographic code uses toy parameters and gives no security.
- No hardware acceleration (AVX-512, CUDA) is reproduced; timings are single-threaded NumPy on the host recorded in `results_v2/run_metadata.json`.
- The XDP, P4, Mininet and Compose files are written but were not compiled or started when the package was assembled.
- Scenarios are feature-level; no live attack tool is shipped. Run any live replay only on an isolated lab you own or are authorised to test.

See `docs/v2/10_limitations_and_open_questions.md` for the open questions the testbed should answer.
