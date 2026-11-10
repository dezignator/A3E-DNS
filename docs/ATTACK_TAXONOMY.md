# ATTACK TAXONOMY — A³E-DNS

**Thesis Chapter 6 · Table 30 (6 classes), Table 31 (6 phases),
Table 32 (S1–S5), §6.15.2–§6.15.4 (protocol-specific)**

This document expands the attack taxonomy used throughout the thesis.
It has three layers:

1. **Table 30 — six attack *classes*.** The high-level categories, each
   with a mechanism, a framework response, and a countermeasure command.
2. **Table 31 — six injection *phases*.** The operational pipeline used
   to inject attacks and observe the detection.
3. **Table 32 — five *scenarios* (S1–S5).** The canonical attack
   scenarios used to evaluate the framework, with reported success
   rates and false-negative rates.

Protocol-specific scenarios (DoH, DoT, DoQ) are collected in
`src/attacks/{doh,dot,doq}_attacks.py`.

---

## 1. Six attack classes (Table 30)

### 1.1 Traffic Analysis — Statistical Fingerprinting

**Mechanism.** Timing inference on encrypted traffic; the packet size
is in `[256, 1400]`, and the observable inter-arrival time carries
information about the queried service.

**Framework response.** AEE morphs the timing according to
`Δt' = f(Δt, E(t))`, where `f ∈ F(θ_a)` is a parameterised morphing
function and `E(t)` is the encryption state.

**Countermeasure.**
