# SECURITY ARGUMENTS — A³E-DNS

**Thesis Chapter 6 · §5.2.6 (KEM combiner), §5.3.5 (IND-CPA of QHE),
§6.4.1 (heuristic AEE schedule), §7.3.5 (threat model), §7.3.6 (scope)**

This document states the security arguments that the thesis makes —
and, equally important, the security arguments that it does **not**
make. It is the reference for what the artifact can and cannot be
cited for when someone asks "is this secure?".

The short answer is: **the artifact makes very narrow security
claims.** They are listed below with their exact scope. Everything
else in the artifact — AEE, FL, Transformer, AMPS, threat intelligence
— is **empirical only**: it was evaluated on the testbed and the
reported metrics are the evidence, not a proof.

---

## 1. Proposition 1 — the KEM combiner (§5.2.6)

### 1.1 Statement

Let `KEM₁` and `KEM₂` be two key-encapsulation mechanisms combined in a
shard. Let
K_ctrl = KDF(ss₁ ‖ ss₂ ‖ ct₁ ‖ ct₂ ‖ ctx)

where `(ct_i, ss_i) ← Encaps_i(pk_i)` for `i ∈ {1, 2}`, and `ctx` is the
session context. **If at least one of `KEM₁` or `KEM₂` is IND-CCA2
secure and `KDF` is a pseudorandom function or a random oracle, then
the combined KEM that outputs `K_ctrl` is IND-CCA2 secure.**

### 1.2 What the thesis does and does not do

- **Does:** cite the standard combiner result (§5.2.6), instantiate it
  with the specific hash of both shared secrets, both ciphertexts, and
  the session context, and use it for the control-plane key of the
  AEE shard.
- **Does not:** re-derive the result, prove a new hybrid-game argument,
  or claim a reduction beyond the published one.

### 1.3 What follows for the artifact

The AEE shard's **control-plane key** is IND-CCA2 as long as the
combiner result applies. This is the **only** formal security claim in
the thesis that is not already a citation.

### 1.4 What does not follow

The Proposition does **not** say that:

- The AEE **key-evolution schedule** (Eqs. 119–122) is secure. It is a
  heuristic construction (see §3 below).
- The AEE **shard ciphertexts** are IND-CCA2. Only the combiner output
  is, and only if the combiner result applies.
- The **rest of the framework** — QHE, FL, AMPS — is secure. Their
  security is discussed separately and, for most of them, not claimed.

---

## 2. IND-CPA of QHE (§5.3.5)

### 2.1 Statement

The Quantum-Safe Homomorphic Encryption layer is **IND-CPA secure under
the decisional Ring-LWE assumption** (reference [198, 199] in the
thesis bibliography, cited not re-derived).

### 2.2 What the thesis does and does not do

- **Does:** cite the standard IND-CPA result for Ring-LWE encryption,
  state the parameters `n = 256`, `q = 4096`, and explain that the
  security target for the parameter set is 128-bit post-quantum under
  the standard lattice-estimator heuristics.
- **Does not:** claim IND-CCA2, claim ciphertext integrity, or claim
  that any specific lattice-estimator version is the authoritative
  one.

### 2.3 What follows for the artifact

The QHE layer provides **confidentiality** (IND-CPA) for the encrypted
feature vectors. It does **not** provide integrity: the scheme is
malleable by design.

### 2.4 What does not follow

- **IND-CCA2.** A homomorphic scheme that is IND-CCA2 is, by
  definition, not homomorphic. The QHE layer is not, and cannot be,
  IND-CCA2.
- **Integrity.** The QHE layer does not detect tampering. Integrity is
  provided by the **authenticated transport** (TLS 1.3 for DoH/DoT,
  QUIC + TLS 1.3 for DoQ), not by the HE layer.
- **Authenticity.** The QHE layer does not authenticate the sender. The
  authenticated transport does.
- **Quantum resistance beyond the assumption.** The IND-CPA argument
  rests on decisional Ring-LWE, which is conjectured to resist quantum
  attack; this is a conjecture, not a theorem.

---

## 3. The AEE key-evolution schedule is a heuristic

### 3.1 Statement

The AEE **key-evolution schedule** (Eqs. 119–122, §6.4) is a **heuristic
construction** that re-randomizes the encryption state over time using
traffic entropy and hardware entropy. It is **not** claimed to be
IND-CCA2, IND-CPA, or secure in any formal sense by itself.

### 3.2 Why it is heuristic

- The state evolution is an **Euler–Maruyama discretization** of a
  stochastic differential equation on `SE(3)ⁿ`. It is not a
  cryptographic construction with a known reduction.
- The diffusion coefficient `σ(t)` is a monotone function of the
  KL divergence between the observed traffic and a baseline. This is
  an engineering choice, not a cryptographic one.
- The session key is derived via `KDF(quantized_state)` where `KDF` is
  SHA-256 with a domain separator. The `KDF` is a standard PRF; the
  **input** is not.

### 3.3 What the thesis does and does not claim

- **Does:** state that the schedule is heuristic (§6.4.1, §6.4.4) and
  that the formal security argument is reserved for the **KEM layer**
  (Proposition 1).
- **Does not:** claim that the schedule is secure by itself. The
  session key that the schedule produces is only as secure as the KDF
  applied to it; the schedule's contribution is **defence in depth**,
  not a standalone guarantee.

### 3.4 What follows for the artifact

The AEE engine (`src/models/aee_engine.py`) implements the schedule.
The engine's docstring and its `metadata()` both mark the schedule as
heuristic. The engine is used in the pipeline as a **defence-in-depth**
layer, not as a standalone cryptographic primitive.

---

## 4. The detection modules are empirical only

### 4.1 What this covers

- **Adaptive Evolutionary Encryption engine** — evaluated empirically
  in Chapter 6; no provable-security claim.
- **Federated learning coordinator and transformer** — evaluated
  empirically; no provable-security claim.
- **Anomaly detector** — evaluated empirically; no provable-security
  claim.
- **Adaptive Multi-Protocol Sandbox** — evaluated empirically; no
  provable-security claim.
- **Threat intelligence integration** — evaluated empirically; no
  provable-security claim.

### 4.2 What the thesis reports for them

For each of these modules, the thesis reports detection accuracy,
false-positive rate, latency, throughput, adversarial robustness, and
(for FL) the differential-privacy budget. These are the evidence.

### 4.3 What the thesis does NOT claim for them

- No provable-security claim.
- No information-theoretic guarantee.
- No guarantee against an adversary with the capability to break the
  underlying transport, the underlying hardware, or the underlying
  learning algorithm.
- No guarantee that the reported empirical metrics generalise beyond
  the testbed described in §6.11.1.

---

## 5. Threat model (§7.3.5)

### 5.1 What is in scope

- **Adaptive network adversaries.** The threat model assumes adversaries
  who can generate arbitrary traffic, apply timing and traffic control,
  alter domain-generation functions, probe for observable cryptographic
  timing patterns, and adapt to defence.
- **Attacks analysed:** polymorphic traffic shaping, staged tunnelling,
  adaptive mimicry, protocol downgrade, quantum key harvesting,
  timing-based side-channel, and GAN-generated adversarial queries.
- **Real-world encrypted-DNS logs with simulated adversarial DNS
  settings.**

### 5.2 What is out of scope

- **Attacks that break TLS 1.3 itself.** The threat model assumes
  TLS 1.3 provides confidentiality and integrity.
- **Direct cryptanalysis of TLS 1.3 sessions.** The threat model assumes
  no classical cryptanalysis of TLS 1.3 is feasible for current or
  foreseeable adversaries.
- **Nation-state adversaries.** Not modelled — not because they are
  considered unable to compromise the architecture, but because their
  computational resources, intelligence, physical access, supply-chain
  influence and ability to intercept at large scale are outside the
  scope of network-level evaluation.
- **Physical attacks** on hardware.
- **Side-channel attacks** beyond the classical timing / power / EM
  models evaluated in the testbed.
- **Cryptanalytic advances** beyond the assumed security foundations.

### 5.3 What this means for the security claims

The security claims in this document are **bounded by the threat
model**. If an adversary has capabilities outside the threat model, the
security claims do not apply. This is stated in §1.7.2 of the thesis
and repeated here.

---

## 6. Quantum resistance is conjectural

### 6.1 What the thesis claims

The post-quantum resistance of the framework rests on:

- **Module-LWE** (AEE key-encapsulation layer)
- **Ring-LWE** (QHE layer)

Both are standard, published lattice problems. Both are conjectured to
resist quantum attack.

### 6.2 What the thesis does NOT claim

- **Unconditional post-quantum security.** No such claim is made.
- **A theorem.** There is no proof that Module-LWE or Ring-LWE resist
  quantum attack; they are conjectures.
- **A specific security level.** The thesis reports the estimated
  security level from the standard lattice-estimator methodology, not a
  proven level.
- **Resistance against all quantum algorithms.** Only against the
  algorithms that are currently believed to be relevant (Shor for the
  underlying hardness assumption, Grover for symmetric search).

### 6.3 Symmetric components

Symmetric components are held at **256 bits**, so that Grover's search
does not reduce their effective strength below 128 bits. This is a
separate decision from the lattice-parameter choice.

---

## 7. What the artifact can and cannot be cited for

### 7.1 Can be cited for

- The **architecture** described in §6.3.
- The **integration contribution** described in §7.2.2.
- The **engineering contribution** described in §7.2.3.
- The **empirical findings** reported in Chapter 6 and summarised in
  `README.md` and Table 33.
- The **KEM combiner argument** (Proposition 1, §5.2.6) as a citation
  of the published result.
- The **IND-CPA of QHE** (§5.3.5) as a citation of the published result.

### 7.2 Cannot be cited for

- **A new cryptographic primitive.** No new primitive is proposed.
- **A new theorem.** No new theorem is proved.
- **A formal security proof for the detection modules.** None exists
  in the thesis.
- **Super-additivity of the integration.** Not established (§7.3.1).
- **A head-to-head advantage over HERALD or ThreatGuard-DNS.** Only a
  qualitative comparison in Tables 1–4.
- **Generalisation to production resolvers.** The empirical findings
  are properties of the testbed described in §6.11.1.
- **Unconditional post-quantum security.** Only conjectural, under the
  published hardness assumptions.

---

## 8. Cross-references

- **`docs/LIMITATIONS.md` §5** — the threat-model and formal-security
  limitations, restated in the §7.3 format.
- **`docs/LIMITATIONS.md` §6** — the theoretical-scope limitation
  (no new theorem, no new primitive).
- **`docs/ARCHITECTURE.md` §5** — what the architecture does not do.
- **`docs/HARDWARE_EMULATION.md` §6** — common misreadings about the
  emulators and security.
- **`src/models/qhe_engine.py`** — the engine's docstring restates the
  IND-CPA / non-IND-CCA2 distinction.
- **`src/models/aee_engine.py`** — the engine's docstring restates the
  heuristic status of the schedule.
