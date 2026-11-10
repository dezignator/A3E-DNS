# LIMITATIONS

**A³E-DNS Thesis Artifact · Chapter 6 · §7.3 carried over**

This file records the limitations of the thesis that qualify every claim
made by this artifact. They are stated here in the order of their
consequence for the central claims. They are not incidental
qualifications — each one bounds what the thesis, and therefore this
artifact, can legitimately be said to have shown.

The full discussion is in `docs/LIMITATIONS.md`; this root file is the
thesis-aligned summary required by §7.3 and is reproduced here so that
it travels with the repository and not only with the documentation.

---

## 1. Absence of a full factorial ablation (§7.3.1)

**The most significant limitation.** No full factorial ablation was
performed. The experiments reported in Chapters 3–6 evaluate each
**complete framework** on its own testbed; the contribution of any
individual component, or any pairwise combination of components, to the
end-to-end results is **not** isolated by any experiment in this
thesis.

In particular, the thesis **does not** show that the integration of
Adaptive Evolutionary Encryption, Quantum-Safe Homomorphic Encryption
and AI-Augmented Federated Learning is super-additive, additive, or
sub-additive. The integrated architecture reported in Chapter 6 was
evaluated as a whole; how much of the 99.94 % accuracy, 0.17 % FPR,
1.42 ms P99 latency and 22.5 M QPS throughput is attributable to each
component versus to the interaction between them is not established.

The ablation is identified as **the first priority for future work** in
§8.2.9. It is the form of evidence that would be required before any
super-additivity claim could be made.

**What this artifact therefore does NOT support:**
- Any claim that the integration outperforms its best-tuned subset.
- Any claim that removing a component would degrade the reported numbers.
- Any claim that reordering the components would change the reported numbers.
- Any claim that the reported figures cannot be explained by a simpler
  feed-forward pipeline.

---

## 2. Baseline comparison restricted in scope (§7.3.2)

The quantitative comparison uses **DNSGuard** and **DeepFingerprint**,
both reproduced and retrained on the same data, same preprocessing and
same tuning budget as A³E-DNS (§6.16.2). The closest published
integrated systems — **HERALD**, **MTL-DoHTA**, **ThreatGuard-DNS**,
**FL-DNSnet**, **QuantumShield-QUIC** — are compared **qualitatively
only** (Tables 1–4 of the thesis). They were **not** re-run on the same
data, hardware or tuning budget.

**Consequence.** The claim of superiority holds against the *reproduced
baselines* (DNSGuard, DeepFingerprint) on the specific testbed described
in §6.11.1. It does **not** hold against the qualitative baselines as a
head-to-head claim. The thesis is careful to state this; this file
repeats it for the artifact.

**Additional note.** The baseline suite is not constant across
chapters: Chapter 3 uses CNN-LSTM and Random Forest; Chapter 4 uses a
DoH comparator set; Chapter 5 uses MTL-DoHTA, ThreatGuard-DNS and
FL-DNSnet qualitatively; Chapter 6 uses DNSGuard and DeepFingerprint.
No single fixed baseline suite is built across all four frameworks.

---

## 3. Statistical reporting and evaluation depth (§7.3.3)

Confidence intervals are reported throughout Chapters 3–6. **Per-class
sample counts, formal hypothesis tests, and held-out adversarial test
sets are not reported** for Chapters 3–5. Only Chapter 6 reports a
*t*-test (*p* < 0.0001) for accuracy and Cohen's *d* = 1.87 for the
FPR comparison against DNSGuard and DeepFingerprint.

The confidence intervals reported in Chapters 3–5 indicate the spread of
measurements; they do not establish statistical significance of the
difference between the proposed systems and their baselines in the sense
of a controlled hypothesis test.

The extremely low error rates reported in some experiments (e.g. the
0.0008 % false-positive rate in one Chapter-3 configuration) make it
difficult to assert that the benchmark was not trivially easy. The full
demonstration that it was not has not been provided.

Generalisation across resolvers was not tested; residual failures were
not analysed by attack family.

**Consequence.** These omissions do not invalidate the reported
measurements, but they restrict the strength of inference from them.

---

## 4. Reproducibility: hardware emulation (§7.3.4)

- **NVIDIA A100** (6,912 CUDA cores, 40 GB HBM) is **emulated**
  (`src/hardware_simulation/a100_emulation.py`).
- **Intel Loihi 2** is **emulated** (`src/hardware_simulation/loihi_mock.py`).
- **P4** is **BMv2-emulated** (`src/dataplane/p4_pipeline/`, Mininet topology).

The emulators reproduce the *trends* reported in the thesis; the
**absolute** figures on real hardware will differ. The distinction
between CPU-reproducible and hardware-bound artifacts is recorded in
`REPRODUCIBILITY_CHECKLIST.md`. Tier B (hardware-emulated) is the
intended reproduction path for independent reviewers.

---

## 5. Threat model and formal security claims (§7.3.5)

Security assertions for this thesis are made **only** for the
control-plane channel of the Metamorphic Cryptographic Shards
(Proposition 1, §3.10.2). Proposition 1 is the standard KEM-combiner
result — `K_ctrl = KDF(ss1 ‖ ss2 ‖ ct1 ‖ ct2 ‖ ctx)` is IND-CCA2 if at
least one KEM is IND-CCA2 and the KDF is a PRF or a random oracle. It is
**cited**, not re-derived.

- The **homomorphic-encryption layer** (QHE) is IND-CPA under
  decisional Ring-LWE. It is malleable by design and does **not**
  provide ciphertext integrity. Integrity is provided by the
  authenticated transport (TLS 1.3 for DoH/DoT, QUIC + TLS 1.3 for DoQ),
  **not** by the HE layer. No IND-CCA2 claim is made for QHE.
- **Detection modules** (AEE, FL, Transformer, Sandbox) are evaluated
  **empirically only**. No provable-security claim is made for them.
- The threat model **excludes**:
  - attacks that break TLS 1.3 itself,
  - direct cryptanalysis of TLS 1.3 sessions,
  - nation-state adversaries,
  - physical attacks on the hardware,
  - side-channel attacks beyond the classical timing / power / EM models
    evaluated in the testbed.
- The **quantum-resistance claim is conjectural**, not a theorem. It
  rests on the assumed hardness of Module-LWE (AEE key-encapsulation
  layer) and Ring-LWE (QHE layer), both of which are standard published
  problems, and both of which are conjectured rather than proven to
  resist quantum attack.
- **Symmetric components** are held at 256 bits so that Grover-type
  search does not reduce their effective strength below 128 bits. This
  is a separate decision from the lattice-parameter choice.

---

## 6. Theoretical scope (§7.3.6)

The thesis does **not** contribute:
- a new theorem,
- a new game-based security definition,
- a new reduction,
- a new cryptographic primitive,
- a new learning algorithm,
- a new proof system.

An earlier draft contained a "Unified Cognitive Security Theorem" that
combined a topological dimension and a cryptographic security parameter
in an undefined ratio; it was not accompanied by a proof and has been
**deleted**. It is replaced by Proposition 1, which is a proposition
about the KEM combiner at a level of precision consistent with the
underlying published results.

If the thesis has novelty, it is **empirical and architectural**, not
theoretical-cryptographic.

---

## 7. External validity (§7.3.7)

The experiments were carried out using public data and a containerised
4-node testbed (Intel Xeon Silver + AMD EPYC, 128 GB DDR4, Ubuntu Server
22.04 LTS, Docker + Minikube, per §6.11.1). The distribution of traffic,
query rates and attack families in these datasets are **not guaranteed
to be representative** of all operational encrypted-DNS environments.

Generalisation to production resolver traffic, to traffic conditions
not represented in the test set, and to deployments at different scale
was **not** tested.

**Consequence.** The external validity of the empirical findings is
limited to the testbed and datasets described in Chapters 3–6.

---

## 8. QHE parameter inconsistency (§6.5 vs Table 27)

This is a **documented internal thesis inconsistency**, not a
limitation of the framework itself.

- **§6.5 of the thesis** states the QHE parameters are `n = 256`,
  `q = 4096`.
- **Table 27 of the thesis** shows the QHE service command line as
  `qhe-service -lattice-dimension 1024 -modulus 3329 -parallel 8`.

The two are not the same parameterisation. This artifact reproduces
both values **verbatim** — the `n = 256, q = 4096` figure in the
`README.md` core-components table and the `-lattice-dimension 1024
-modulus 3329` command in the Table 27 section — and does **not**
silently correct either one. The inconsistency is flagged here so that
any reader who reproduces the artifact is aware that:

1. The QHE parameters reported in §6.5 and used in the evaluation are
   `n = 256, q = 4096`.
2. The Table 27 command line is **not** the parameter set used to obtain
   the reported QHE numbers. It is presented as-is for fidelity to the
   thesis.
3. A corrected Table 27 command line, consistent with §6.5, would read
   something like `qhe-service -lattice-dimension 256 -modulus 4096
   -parallel 8` — but that correction is **not** made in this artifact.

**Recommended resolution.** The inconsistency should be resolved in the
thesis itself (either §6.5 or Table 27 should be updated so that they
match), and the artifact updated to follow the corrected thesis. Until
then, this artifact stays thesis-accurate and flags the discrepancy.

---

## Cross-references

- §7.3.1 → §8.2.9 (full factorial ablation is future work item 1)
- §7.3.2 → §8.2.10 (head-to-head with HERALD and ThreatGuard-DNS is future work item 2)
- §7.3.3 → §8.2.12 (statistical and external-validity extensions are future work)
- §7.3.4 → `REPRODUCIBILITY_CHECKLIST.md` (tier A / B / C / D)
- §7.3.5 → `docs/SECURITY_ARGUMENTS.md`
- §7.3.6 → §7.2.1 (scientific contribution is empirical, not theoretical)
- §7.3.7 → `docs/TESTBED.md` (testbed is a 4-node containerised environment)

---

## Full statement

The full statement of every limitation, with the surrounding discussion
from Chapter 7 of the thesis, is in [`docs/LIMITATIONS.md`](./docs/LIMITATIONS.md).
This root-level file is the §7.3 summary required by the thesis artifact
and is intentionally concise.
