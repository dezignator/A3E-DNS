//! Python bindings for the A3E-DNS Rust core.
//!
//! This module is compiled only when the `python` feature is enabled.
//! It exposes the same function names as the NumPy implementations in
//! `extended_experimentation.qhe` and `extended_experimentation.aee`, so
//! that the pipeline can transparently prefer the Rust path when the
//! extension is importable.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use crate::field::Q;
use crate::ntt::{negacyclic_forward, negacyclic_inverse, N};
use crate::sampler::{GaussianSampler, SplitMix64};
use crate::se3::se3_exp_flat;

#[pyfunction]
fn ntt_forward(coeffs: Vec<u32>) -> PyResult<Vec<u32>> {
    if coeffs.len() != N {
        return Err(PyValueError::new_err(format!(
            "expected {} coefficients, got {}",
            N,
            coeffs.len()
        )));
    }
    let mut arr = [0u32; N];
    arr.copy_from_slice(&coeffs);
    negacyclic_forward(&mut arr);
    Ok(arr.to_vec())
}

#[pyfunction]
fn ntt_inverse(coeffs: Vec<u32>) -> PyResult<Vec<u32>> {
    if coeffs.len() != N {
        return Err(PyValueError::new_err(format!(
            "expected {} coefficients, got {}",
            N,
            coeffs.len()
        )));
    }
    let mut arr = [0u32; N];
    arr.copy_from_slice(&coeffs);
    negacyclic_inverse(&mut arr);
    Ok(arr.to_vec())
}

#[pyfunction]
fn sample_gaussian(n: usize, seed: u64) -> Vec<i32> {
    let s = GaussianSampler::default_ml_dsa();
    let mut rng = SplitMix64::new(seed);
    s.sample_many(&mut rng, n)
}

#[pyfunction]
fn se3_exp_py(xi: Vec<f64>) -> PyResult<Vec<f64>> {
    if xi.len() != 6 {
        return Err(PyValueError::new_err(format!(
            "expected 6 elements, got {}",
            xi.len()
        )));
    }
    let mut arr = [0.0f64; 6];
    arr.copy_from_slice(&xi);
    Ok(se3_exp_flat(arr).to_vec())
}

#[pyfunction]
fn modulus() -> u32 {
    Q
}

#[pymodule]
fn a3e_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ntt_forward, m)?)?;
    m.add_function(wrap_pyfunction!(ntt_inverse, m)?)?;
    m.add_function(wrap_pyfunction!(sample_gaussian, m)?)?;
    m.add_function(wrap_pyfunction!(se3_exp_py, m)?)?;
    m.add_function(wrap_pyfunction!(modulus, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("Q", Q)?;
    m.add("N", N)?;
    Ok(())
}
