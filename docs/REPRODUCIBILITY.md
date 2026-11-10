# REPRODUCIBILITY — Protocol and Artifact

**Thesis Chapter 6 · §7.3.4, §7.3.7, §8.2.9, §8.2.12**

This document specifies the reproducibility protocol for the A³E-DNS
artifact: what a reproduction run consists of, what is deterministic,
what is emulated, what is not reproducible, and what the reviewer
should expect to see at the end.

It is the detailed companion to `REPRODUCIBILITY_CHECKLIST.md` (the
short operational checklist) and `docs/HARDWARE_EMULATION.md` (the
hardware model).

---

## 1. What "reproduce the artifact" means

A reproduction run is a **four-step workflow**:

1. **Setup.** Install the pinned dependencies (`requirements.txt`) and
   the package (`setup.py develop`).
2. **Data.** Download (or generate) the datasets used by the artifact.
   Toy mode uses a schema-matched synthetic dataset; full mode uses the
   real 32 GB Zenodo + DoH-RealWorld + Kosekmi-2022 data.
3. **Run.** Execute the training loop and the reproduction scripts:
   `scripts/train_a3e.py`, then `scripts/reproduce_all.sh`.
4. **Verify.** Compare the fresh outputs against the committed
   references in `expected_outputs/`, using
   `expected_outputs/verification_script.py`.

The workflow must complete with **exit code 0** for the reproduction to
count as successful. The verification step produces a line-per-artifact
report; a `MISMATCH` line indicates a deviation.

---

## 2. What is deterministic

Given the same seed (`20261130`), the same mode, and the same checkout:

- **Every JSON output** from `scripts/reproduce_tables/*` is
  byte-identical across runs.
- **Figure 14 (SVG)** is byte-identical across runs.
- **The AEE engine's state evolution** (given the same controller
  and the same traffic input) is deterministic.
- **The FL coordinator's rounds** (given the same client updates) are
  deterministic.
- **The attack simulators** in `src/attacks/*` are deterministic given
  their per-scenario `seed`.
- **The compliance checkers** are deterministic given the same
  configuration.

## 3. What is NOT deterministic

- **Wall-clock latencies** on real hardware (A100, Loihi, P4 switch).
  These are hardware properties; the thesis reports them as measured on
  the testbed of §6.11.1.
- **The emulators' absolute numbers.** The A100 and BMv2 emulators
  preserve trends, not absolute values. Loihi emulator returns the
  reported figures exactly (it is a fixed model).
- **GPU non-determinism** on CUDA operations that do not have a
  deterministic implementation. The `src/utils/seed.py` module sets
  `torch.use_deterministic_algorithms(True, warn_only=True)` so that
  the artifact degrades gracefully rather than crashing.
- **Thread / process scheduling** in Dask, gRPC, and the Docker
  network. The dataset-level results are deterministic; the scheduling
  timings are not.

---

## 4. The reproducibility tiers

The artifact is reproducible at four tiers (see
`REPRODUCIBILITY_CHECKLIST.md` for the full matrix):

| Tier | Command | Runtime | Fidelity |
|---|---|---|---|
| A | `make toy` | ~2 min | Schema-matched synthetic; structural only |
| B | `make medium` | ~45 min | Toy + A100 emulated + P4 emulated |
| C | (real hardware) | varies | Real 32 GB data + real A100 / Loihi / P4 |
| D | `make full` | 6–9 h | Tier B + real 32 GB data |

**Reviewer guidance:**

- If you have a 16-core x86-64 machine and no special hardware, use
  **Tier A** to check the artifact's structure and JSON outputs.
- If you want to exercise the full pipeline including AEE, QHE and
  AMPS, use **Tier B**.
- If you have the A100 / Loihi / P4 hardware, use **Tier C** and
  expect absolute numbers to differ from the committed reference
  (see `docs/HARDWARE_EMULATION.md` §6 for what to do about that).
- If you want to reproduce the exact numbers in the thesis, use
  **Tier D**, which is the closest the artifact can come.

---

## 5. The seed policy

All seeds in the artifact derive from a single master seed
(`20261130`, the thesis submission date). Per-call-site seeds are
derived via `src.utils.seed.rng_for(name, base_seed)`, which hashes
`f"{base_seed}::{name}"` with SHA-256 and uses the first 8 bytes as
the per-site seed.

**Why this policy?** Re-seeding the global RNG at every call site
creates a hidden coupling between call sites (changing one changes
all). Deriving per-site seeds from the master seed keeps them
independent while preserving determinism.

**To reproduce with a different seed:** pass `--seed N` to any script
that accepts it. The scripts that accept `--seed` are:
`scripts/train_a3e.py`, `scripts/run_dask_pipeline.py`, and all figure
scripts. The table scripts use the configuration seed from
`configs/*.yaml`, which you can override by editing the YAML.

---

## 6. Reference outputs

The committed references in `expected_outputs/` are the values the
verification script checks against. They are **thesis-aligned**, not
hardware-agnostic:

- For Tier A artifacts (JSON outputs, Figure 14, Figure 15), the
  reference is byte-identical to what a Tier A run produces.
- For Tier B artifacts (Tables 31, 32, 33; Figures 16, 17, 18, 19),
  the reference is produced by the **emulators**, not by the real
  hardware. The reference therefore reflects the emulated values; the
  thesis reports real-hardware values.

This means that the verification script will report `OK` for a Tier B
run and `OK` for a Tier A run — but it does not report whether the
absolute values on the reviewer's hardware match the thesis. The
thesis's absolute figures are properties of the testbed described in
§6.11.1; see `docs/HARDWARE_EMULATION.md` §6.

---

## 7. Verification protocol

The verification script (`expected_outputs/verification_script.py`)
performs two checks:

### 7.1 Reference comparison

For each selected artifact, the script:

1. Runs the corresponding reproduction script (with the `--mode` and
   `--output` it was given).
2. Reads the newly written reference file.
3. Compares it field-by-field against the previously committed
   reference, using the tolerance passed on the command line.

Numeric fields are compared as `abs(actual - expected) <= tolerance`.
String and categorical fields must match exactly. JSON structure is
compared recursively; any difference in length, key set, or type is
reported as a `MISMATCH` with the full JSON pointer path.

### 7.2 Explicit verification targets

After the reference comparison, the script checks the explicit
verification targets from §6.16:

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

If any of these is outside its tolerance, the script exits non-zero
even if the reference comparison passed.

### 7.3 What to do on failure

1. **If a reference comparison failed**, the fresh run produced a
   different output. The most likely causes are:
   - A configuration change in `configs/`.
   - A code change in one of the modules.
   - A library version mismatch (`pip freeze` and compare with
     `requirements.txt`).
   - Hardware non-determinism (for Tier B / C artifacts).
2. **If an explicit verification target failed**, the fresh run's
   reported numbers diverged from the thesis. The most likely causes
   are the same as above, plus the hardware-related ones.
3. **Do not silently overwrite the reference.** Either fix the
   underlying issue or, if the change is intentional (e.g. a bug fix
   that legitimately changes the output), document the change in the
   commit message, update `STATUS.md`, and regenerate
   `expected_outputs/MANIFEST.sha256`.

---

## 8. What a successful reproduction shows

A successful reproduction of the artifact shows that:

- The **architecture** described in §6.3 is implemented and runnable.
- The **tables and figures** of Chapter 6 can be reproduced from the
  committed code and configuration, within the documented tolerances.
- The **verification targets** from §6.16 can be achieved on the
  artifact's testbed configuration.

It does **not** show that:

- The integration is super-additive (§7.3.1; `docs/LIMITATIONS.md` §1).
- The absolute figures generalise to a production resolver
  (§7.3.7; `docs/LIMITATIONS.md` §7).
- The absolute figures on real hardware match the emulated figures
  (they don't; see `docs/HARDWARE_EMULATION.md` §6).

The reproducibility of the artifact is a stronger statement than the
reproducibility of the thesis's absolute numbers, because the artifact
reproduces the **structure, the protocol, and the trends** even when
it cannot reproduce the **absolute values** on a machine that does not
have the thesis's hardware.

---

## 9. What the reviewer should report

If a reviewer runs the artifact and gets a different result, the most
useful report includes:

1. **The command that was run** (verbatim).
2. **The exit code** of that command.
3. **The full output** of `verification_script.py`.
4. **`python --version`** and **`uname -a`**.
5. **`pip freeze`** (or at least `pip show` for the packages in
   `requirements.txt`).
6. **`nvidia-smi`** (if available), **`lscpu`** (for CPU-only runs).
7. **Whether the run was `--cpu-only`** (i.e. which tier).
8. **The `git rev-parse HEAD`** of the checkout.

The maintainers can then compare against the reference commit and
determine whether the difference is a real regression, a hardware
effect, or a library version issue.

---

## 10. The reproducibility checklist (see `REPRODUCIBILITY_CHECKLIST.md`)

The four tiers map to four checklists:

- **Tier A** — 4 steps, ~2 min, no external data, no special hardware.
- **Tier B** — 7 steps, ~45 min, no external data, emulated hardware.
- **Tier C** — 8 steps, varies, real hardware, real 32 GB data.
- **Tier D** — 9 steps, ~6–9 h, real 32 GB data, no special hardware
  required (the emulators cover the hardware).

The checklist in `REPRODUCIBILITY_CHECKLIST.md` is the operational
version of this document. If the two ever disagree, the checklist wins.
