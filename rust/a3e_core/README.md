# a3e_core — Rust implementation of A3E-DNS cryptographic primitives

This crate provides the three cryptographic primitives that the A3E-DNS
extended experimentation suite relies on, implemented in Rust with no
mandatory dependencies beyond the standard library:

- the negacyclic number-theoretic transform over `Z_Q[X]/(X^N + 1)`,
- the CDT Gaussian sampler with the ML-DSA parameter set (`σ = 3.2`,
  `tail = 6σ`),
- the SE(3) exponential map and the AEE state evolution.

## Building

Without Python bindings:

```bash
cargo build --release
