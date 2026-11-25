# 01. Traceability from Chapter 6 to the v2 files

This table lists, for every subsection of Chapter 6, what the v2 package contains and how far it goes. "Implemented" means executable code with unit tests in `tests_v2/`. "Harness result" means an experiment in `experiments_v2/` that writes tables and figures. "Not reproduced" means the item depends on hardware or software that the harness does not have; we say so rather than approximate it.

| Chapter 6 section | Content | v2 file(s) | Status |
|---|---|---|---|
| 6.2.1 Time-evolving traffic space | feature space over flow windows | `src/a3e_dns_v2/traffic.py` | Implemented (16 features, three protocols) |
| 6.2.2 Adversarial generative operators | PGD and blending evasion | `experiments_v2/common.py` (`pgd`), `e1_detection.py` (E9) | Implemented, harness result |
| 6.2.3 Byzantine threat model | f < N/2 malicious clients | `fl/simulate.py`, `e2_federated.py` | Implemented, harness result |
| 6.3.3 Pipeline, Eq. (117) | P = S_eBPF o F_QHE o AFL o M_sandbox | `src/a3e_dns_v2/pipeline.py` | Implemented (four stages, switchable) |
| 6.4.1 AEE | window of 1,000 packets, KL-driven volatility | `aee/entropy.py`, `aee/controller.py` | Implemented |
| 6.4.2 SE(3) state | closed-form exponential, key and IV derivation | `aee/se3.py`, `e5_aee.py` (E5a) | Implemented |
| 6.4.3 Hardware entropy | RDRAND/RDSEED plus system entropy, whitened | `aee/entropy.py` | Partial: `os.urandom` mixed through SHA3 (Python cannot issue RDRAND) |
| 6.4.4 Key evolution, Eqs. (121)-(122) | SDE with floored diffusion | `aee/evolution.py`, E5c/E5d | Implemented |
| 6.4.5 Neural controller | 2 x 64 units, quantisation, pruning | `aee/controller.py`, E5e | Implemented |
| 6.5.1 NTT and SIMD | negacyclic NTT | `qhe/ring.py`, E4c | NTT implemented; AVX-512 and slot packing not reproduced |
| 6.5.2 Gaussian sampling | pre-computed tables | `qhe/sampler.py`, E4b | Partial: CDT sampler, not the ziggurat layering |
| 6.5.3 Selective operations | process only informative features | `qhe/analytics.py` (`select_features`), E4f | Implemented |
| 6.5.4 CUDA kernels | A100 acceleration | none | Not reproduced |
| 6.5.5 Compression and pipeline | 8:1 compression, depth 3, 16 cores | E4d (packed ciphertext size) | Partial: packing ratio measured, no multi-core pipeline |
| 6.6.1 / 6.6.2 Attention and decay | spatio-temporal attention | `fl/attention.py`, `torch_detector_v2.py` | NumPy forward pass tested; PyTorch model not trained here |
| 6.6.3 Min-max resilience, Eq. (126) | PGD training | `experiments_v2/common.py`, E9, E10 | Implemented (PGD on the MLP detector) |
| 6.6.4 Geometric median, Eqs. (127)-(128) | clipping, Weiszfeld, MAD filter | `fl/robust.py`, E2 | Implemented |
| 6.6.5 DP, Eqs. (129)-(130) | Gaussian mechanism, accountant | `fl/dp.py`, E3 | Implemented (RDP accountant without sub-sampling) |
| 6.7.1 - 6.7.3 Threat intelligence | STIX, honeypot, darknet, vendor feeds | `intel/stix.py`, `intel/honeypot.py`, E8 | Implemented (STIX subset) |
| 6.8 Log correlation and feedback | CEF/syslog correlation | `intel/logcorr.py` | Implemented |
| 6.9.1 CDS, Eq. (131) | harmonic mean of AUPRC and F1w minus JSD term | `metrics.py` (`cds`) | Implemented; JSD sample sets are our reading (see audit) |
| 6.9.2 Quantum resistance metric | lambda = 256 estimate | none | Not reproduced (an estimate, not executable) |
| 6.9.3 Lagrangian, Eqs. (132)-(133) | adaptive learning rate | `fl/schedule.py` | Eq. (133) implemented; Eq. (132) not run |
| 6.10 Performance model, Eqs. (134)-(135) | QPS bound | `metrics.py` (`qps_max`, `eta_adversarial`) | Implemented |
| 6.11 Testbed | nodes, OS, software | `deployment/v2/`, `docs/v2/05_deployment_runbook.md` | Specified, not executed here |
| 6.12 P4 data plane | parser, match-action, metadata | `deployment/v2/p4/a3e_meta_v2.p4`, `ebpf/dns_meta_v2.bpf.c` | Written, not compiled here |
| 6.13 Dask pipeline | chunked preprocessing, splits | `deployment/v2/scripts/dask_preprocess_v2.py` | Written, not run (dataset not available here) |
| 6.14 Benchmarks | crypto, FL, sandbox | E4, E2/E3, E7 | Harness results |
| 6.15 Attack simulation | DoH, DoT, DoQ scenarios | `traffic.py`, `04_attack_scenario_catalogue.md`, E10 | Feature-level scenarios; live tools not shipped |
| 6.16 Results | Tables 32, 33 | `07_thesis_reported_results.md` | Thesis values with recomputation |
| 6.17 Limits | integration claim, trade-offs | `10_limitations_and_open_questions.md`, E6 | Factorial ablation protocol and harness run |
