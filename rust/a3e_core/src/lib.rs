//! A3E-DNS cryptographic primitives.
//!
//! We implemented this crate to provide auditable, dependency-free Rust
//! reference implementations of the three primitives the A3E-DNS
//! extended experimentation suite relies on:
//!
//! * the negacyclic number-theoretic transform over `Z_Q[X]/(X^N + 1)`,
//! * the CDT Gaussian sampler over a discrete Gaussian with a tail bound,
//! * the SE(3) exponential map and its use in the AEE state evolution.
//!
//! The crate is deliberately minimal. It does not implement full BFV or
//! CKKS; the Python side already lives on top of audited libraries when
//! such libraries are available, and the Rust side exists to provide a
//! fast path for the two hot kernels (NTT and sampler) plus a numerical
//! foundation for the AEE state that the NumPy implementation could not
//! offer without pulling in a full linear-algebra stack.
//!
//! When compiled with `--features python`, the crate produces a Python
//! extension module that exposes the same function names as
//! `extended_experimentation.qhe.quantum_safe_homomorphic_engine` and
//! `extended_experimentation.aee.adaptive_evolutionary_encryption`. The
//! pipeline checks for the Rust extension at startup and falls back to
//! the NumPy implementation if it is absent, so a reviewer without a Rust
//! toolchain still has a working Python path.

pub mod field;
pub mod ntt;
pub mod sampler;
pub mod se3;

#[cfg(feature = "python")]
mod pybindings;

pub use field::{add, mod_inverse, mod_pow, mul, neg, sub, Q};
pub use ntt::{negacyclic_forward, negacyclic_inverse, N, PSI};
pub use sampler::{GaussianSampler, SplitMix64};
pub use se3::{se3_exp, se3_exp_flat, Se3State};
