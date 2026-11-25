# Changelog

## 2.0.0
Added (all new paths carry a `v2` marker so version 1 is untouched):
- `src/a3e_dns_v2/`: AEE (SE(3) state, SDE key evolution, controller, entropy), QHE (RLWE additive scheme, NTT, samplers, encrypted histograms), AFL (attention, robust aggregation, RDP accountant, learning-rate schedule, simulation), intelligence (STIX, honeypot, darknet, CEF correlation), sandbox MDP, metrics (Eq. 131, 133, 134, 135), composite pipeline (Eq. 117).
- `experiments_v2/`: E1 to E10 and `run_all.py`.
- `tests_v2/`: 42 unit tests.
- `docs/v2/`: traceability, parameter registry, threat model, attack catalogue, runbook, evaluation protocol, thesis-results check, consistency audit, harness results, limitations.
- `deployment/v2/`: XDP collector, BMv2 program, Mininet topology, netem profiles, Dask preprocessing, Compose stack.
- `dashboards/a3e_v2_dashboard.html`, `notebooks_v2/`, `configs/v2/`, `data/v2/`, `results_v2/`.

Notes:
- Section references were checked against the text of Chapter 6; the audit lists the places where the chapter gives two values for one item.
