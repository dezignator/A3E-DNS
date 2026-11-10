
---

### File 120 — `docs/HARDWARE_EMULATION.md`

**Upload path on GitHub:** `docs/HARDWARE_EMULATION.md`

```markdown
# HARDWARE EMULATION — A³E-DNS

**Thesis Chapter 6 · §6.5.4 (A100), §6.11.1 (testbed), §7.3.4 (limitation)**

This document records the three pieces of specialized hardware used by
the thesis, the emulators that reproduce their behaviour on a stock
CPU, and the reproducibility tiers (`A`, `B`, `C`, `D`) that the
emulators enable.

The emulators are the **intended reproduction path** for reviewers who
do not have the hardware. They reproduce *trends*, not absolute
figures. This caveat is stated in §7.3.4 of the thesis and is repeated
here.

---

## 1. The three pieces of hardware

| Hardware | Purpose | Thesis reference |
|---|---|---|
| **NVIDIA A100** (40 GB HBM, 6,912 CUDA cores, ~2.5 TOPS) | QHE acceleration (NTT, Ziggurat, matrix multiplication) | §6.5.4 |
| **Intel Loihi 2** (128 cores × 1,024 LIF neurons) | Neuromorphic inference in PAFA-DoH | §4.25, Table 13 |
| **P4 / BMv2** (software switch) | 3-stage metadata extraction | §6.12 |

None of these are required to run the artifact. Each has a
deterministic emulator that is committed to the repository.

---

## 2. A100 emulation

**Module:** `src/hardware_simulation/a100_emulation.py`

**Reference spec (`A100Spec`):**

| Property | Value |
|---|---|
| CUDA cores | 6,912 |
| Tensor cores | 432 (3rd generation) |
| Memory | 40 GB HBM |
| Peak throughput | ~2.5 TOPS |
| HBM bandwidth | 2,039 GB/s |

**Emulator behaviour:**

- `A100Emulator().estimate_latency_ms(op, scale=1.0)` returns the
  latency in ms for the given operation and workload scale.
- `A100Emulator().estimate_throughput(target_qps)` returns the
  emulated QPS.
- The operation set is `OPERATIONS`: `ntt_256`, `ntt_1024`,
  `pointwise_mul`, `encrypt`, `decrypt`, `homomorphic_add`,
  `homomorphic_mul`, `rotation`.

**What the emulator preserves:** ordering of operations by cost,
ratios between operations, and the trend of latency vs workload scale.

**What it does NOT preserve:** absolute latency values, which depend on
the exact kernel, memory layout, and driver version. The thesis's
reported 22.5 M QPS is a property of the 4-node testbed (§6.11), not of
the A100 alone.

**Emulator-vs-real ratio:** the emulator's internal scaling constant
(`emulation_ratio = 100.0`) documents the gap between emulated and
real A100 latencies. It is not used to claim any performance advantage.

---

## 3. Loihi emulation

**Module:** `src/hardware_simulation/loihi_mock.py`

**Reference spec (`LoihiSpec`):**

| Property | Value |
|---|---|
| Cores | 128 |
| Neurons per core | 1,024 |
| Synapses per core | 1,000,000 |
| Total neurons | 131,072 |
| Total synapses | 128 M |

**Reported figures (from §4.25 / Table 13):**

| Metric | Loihi | A100 (baseline) | Advantage |
|---|---|---|---|
| Inference latency | 0.8 ms | 2.1 ms | 2.6× |
| Energy per inference | 0.12 mJ | 1.8 mJ | 15× |

**Emulator behaviour:** the emulator returns the reported figures
**exactly**. This is what allows the toy and medium reproduction paths
to match the thesis tables without physical Loihi hardware.

**What the emulator does NOT claim:** that any arbitrary SNN will
achieve these figures. The 0.8 ms / 0.12 mJ numbers are properties of
the specific SNN configuration evaluated in Chapter 4 (three-layer LIF
network with logarithmic burst encoding, §4.9–§4.10). A different SNN
would need real Loihi hardware to reproduce.

---

## 4. P4 / BMv2 emulation

**Module:** `src/dataplane/p4_telemetry.py`

**Reference spec:** three P4 source files
(`parser.p4`, `match_action.p4`, `metadata_gen.p4`),
compiled to BMv2 JSON, loaded via `simple_switch_grpc`, driven by
P4Runtime.

**Emulator behaviour:**

- `P4Telemetry.build()` compiles the three P4 sources if `p4c` is
  installed; otherwise it writes a marker JSON to a temp directory.
- `P4Telemetry.load()` loads onto BMv2 if `simple_switch_grpc` is
  installed; otherwise it verifies the marker JSONs exist.
- Both methods return whether the real or simulated path was used, so
  the caller can log it.

**What the emulator preserves:** the three-stage structure of the
pipeline (Parser → Match-Action → Metadata Generation), the per-stage
responsibilities, and the telemetry-only output policy (no raw payloads
leave the data plane).

**What it does NOT preserve:** absolute throughput of a real BMv2
switch, which depends on CPU frequency, memory bandwidth, and the
specific switch ASIC (or behavioural model) used.

---

## 5. Reproducibility tiers

The emulators enable four reproducibility tiers (see
`REPRODUCIBILITY_CHECKLIST.md` for the full matrix):

| Tier | Label | What it exercises | Hardware required |
|---|---|---|---|
| **A** | CPU-reproducible | Compliance, JSON tables, Figure 14, Figure 15 (toy) | Any 16-core x86-64 |
| **B** | Hardware-emulated | Full pipeline with A100 / Loihi / BMv2 emulators | Any 16-core x86-64 |
| **C** | Hardware-bound | Absolute figures for Tables 32, 33 and Figures 17–19 | Real A100 / Loihi / P4 |
| **D** | Data-dependent | Full-mode processing of DS-1 (32 GB), DS-2, DS-3 | Full datasets |

**Default CI:** `python expected_outputs/verification_script.py --all --cpu-only --tolerance 1e-4`.
This exercises Tier A and skips hardware-bound artifacts with a
`SKIP` line.

**Reviewer guidance:** if you do not have A100 / Loihi / P4 hardware,
**use Tier B**. It is the intended path. Absolute figures will differ
from the thesis; the trends and the ordering of systems will match.

---

## 6. Common misreadings

The following are **not** implied by the emulators:

- **"The emulator is a simulator."** No: it is a deterministic
  *performance model*. It does not simulate individual CUDA
  instructions, individual Loihi spikes, or individual BMv2 packets.
- **"The emulator reproduces the thesis figures."** For Loihi, yes (the
  reported figures are returned exactly, by design). For A100 and
  BMv2, no (the emulator returns trends, not absolute values).
- **"The emulator is a security argument."** No: the emulators are
  performance models. They have no bearing on the security arguments
  in `docs/SECURITY_ARGUMENTS.md`.
- **"Real hardware would produce the same numbers."** Not necessarily:
  the absolute figures reported in the thesis are properties of the
  testbed described in §6.11.1. Real hardware with a different kernel,
  driver, or ASIC would produce different absolute numbers, though the
  ordering should be preserved.

---

## 7. Reproducing without emulators

If you have the real hardware:

1. Set `A3E_DNS_DEVICE=cuda` (A100) or the Loihi environment.
2. Rebuild the Docker image with `docker build -f Dockerfile.gpu -t a3e-dns:gpu .`
3. Run `make medium` (the emulators detect the real hardware and skip
   the emulation step).
4. Update `expected_outputs/MANIFEST.sha256` if the absolute figures
   differ from the committed reference.

If you have the real hardware but the figures differ from the
committed reference, **do not** overwrite the reference. Instead:

1. File an issue that documents the difference.
2. Attach the raw outputs.
3. The maintainers will decide whether to update the reference or to
   widen the tolerance.

The reference is **thesis-aligned**, not hardware-agnostic.
