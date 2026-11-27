# A3E-DNS extended experimentation suite

This package contains the codebase that produces the extended experimental
artefacts for **Chapter 6** of the thesis *Next-Generation Secure Encrypted
DNS Architectures*. It is structured as a sequence of independently
runnable stages whose outputs feed one another, plus a unified CLI at
`extended_experimentation/cli.py` for discovery.

## Scope

The suite covers:

- the ten-scenario attack catalogue with severity sweeps and adaptive
  variants (S1–S10 in Table 30),
- a federated defence trainer with Byzantine-robust aggregation and a
  Rényi-DP accountant (E2, E3),
- eight Byzantine attack strategies with per-client scheduling
  (Section 6.3, Table 31),
- Adaptive Evolutionary Encryption (AEE) with SE(3) state and a neural
  volatility controller (Section 6.4),
- Quantum-Safe Homomorphic Encryption (QHE) with negacyclic NTT, CDT
  Gaussian sampler and selective operations (Section 6.5, Tables 33–34),
- an E1–E10 orchestrator with a DAG scheduler and artefact verification,
- an end-to-end runtime pipeline with a latency budget (E5, E6),
- statistical significance (paired bootstrap, Wilcoxon, permutation,
  Friedman) (Table 39),
- a component ablation runner (E7, Table 36),
- result tables S1–S9 and figures F1–F7,
- public dataset loaders aligned to the 16-feature A3E schema.

The suite deliberately does not reimplement the ten `e1`–`e10`
experiment scripts under `experiments_v2/`; the orchestrator invokes
them as subprocesses and consumes their manifests.

## Dependencies

| Stage | Requires |
|-------|----------|
| `generate-catalogue`, `load-dataset`, `aee-trace`, `qhe-benchmark` | `numpy` |
| `fl-train`, `byzantine-sweep` | `numpy` (PyTorch optional for larger runs) |
| `pipeline-smoke` | `numpy` |
| `run-e1-e10` | subprocess (the underlying experiment scripts) |
| `significance`, `ablation` | `numpy` |
| `tables` | `numpy` |
| `figures` | `numpy`, optional `matplotlib` |

## Pipeline

```bash
# 1. Generate the attack catalogue.
python -m extended_experimentation.cli generate-catalogue \
    --out runs/catalogue --seed 20231130

# 2. Run the federated defence trainer (E2/E3).
python -m extended_experimentation.cli fl-train \
    --out runs/fl --n-clients 20 --byzantine-fraction 0.20

# 3. Run the Byzantine sweep.
python -m extended_experimentation.cli byzantine-sweep \
    --out runs/byzantine --seed 20231130

# 4. Run the AEE trace and QHE benchmark.
python -m extended_experimentation.cli aee-trace --out runs/aee/aee_trace.json
python -m extended_experimentation.cli qhe-benchmark --out runs/qhe/qhe_benchmark.json

# 5. Sequence E1–E10.
python -m extended_experimentation.cli run-e1-e10 \
    --repository-root . --output-root runs/experiments \
    --resume --parallel --seed 20231130

# 6. Pipeline smoke test.
python -m extended_experimentation.cli pipeline-smoke \
    --out runs/pipeline/smoke.json --n-queries 10000

# 7. Statistical significance, ablation, tables and figures.
python -m extended_experimentation.cli significance \
    --primary runs/a3e_predictions.jsonl \
    --baseline runs/mirage.jsonl runs/pafa.jsonl runs/e3.jsonl \
    --out runs/significance
python -m extended_experimentation.cli ablation \
    --checkpoint-root runs/checkpoints --out runs/ablation
python -m extended_experimentation.cli tables \
    --manifests-root runs/experiments --out runs/tables
python -m extended_experimentation.cli figures \
    --manifests-root runs/experiments --out runs/figures
