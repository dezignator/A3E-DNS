//! Cross-checks against from-scratch reference implementations.
//!
//! We wrote these tests to validate the Rust primitives against
//! straightforward O(N^2) reference implementations. A round-trip test
//! alone would not have proved correctness — an identity transform
//! would pass a round-trip — so the tests below check that the fast
//! path agrees with the slow, obvious one.

use a3e_core::field::{add, mod_inverse, mul, neg, sub, Q};
use a3e_core::ntt::{negacyclic_forward, negacyclic_inverse, N, PSI};
use a3e_core::sampler::{GaussianSampler, SplitMix64};
use a3e_core::se3::se3_exp_flat;

/// O(N^2) negacyclic multiplication over `Z_Q[X]/(X^N + 1)`.
///
/// We used this as the ground truth for the NTT-based convolution.
fn naive_negacyclic_mul(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut result = [0u32; N];
    for i in 0..N {
        for j in 0..N {
            let idx = i + j;
            let product = mul(a[i], b[j]);
            if idx < N {
                result[idx] = add(result[idx], product);
            } else {
                // X^(i+j) = X^(i+j-N) * X^N = -X^(i+j-N).
                result[idx - N] = sub(result[idx - N], product);
            }
        }
    }
    result
}

fn splitmix(seed: u64, n: usize) -> Vec<u32> {
    let mut rng = SplitMix64::new(seed);
    (0..n).map(|_| (rng.next_u64() as u32) % Q).collect()
}

fn to_array(v: &[u32]) -> [u32; N] {
    let mut a = [0u32; N];
    a.copy_from_slice(&v[..N]);
    a
}

#[test]
fn field_arithmetic_round_trips() {
    let values = splitmix(1, 1000);
    for i in 0..values.len() {
        for j in 0..values.len().min(i + 5) {
            let a = values[i];
            let b = values[j];
            assert_eq!(add(sub(a, b), b), a);
            assert_eq!(sub(add(a, b), b), a);
            assert_eq!(mul(a, mod_inverse(a)), 1);
            assert_eq!(neg(neg(a)), a);
        }
    }
}

#[test]
fn ntt_inverse_of_forward_is_identity() {
    let values = splitmix(2, 100);
    for chunk in values.chunks(N) {
        if chunk.len() < N {
            continue;
        }
        let original = to_array(chunk);
        let mut a = original;
        negacyclic_forward(&mut a);
        negacyclic_inverse(&mut a);
        for i in 0..N {
            assert_eq!(a[i], original[i], "coefficient {} mismatch", i);
        }
    }
}

#[test]
fn ntt_agrees_with_naive_multiplication() {
    // Correctness test: the NTT-convolution must equal the naive
    // polynomial multiplication mod (X^N + 1).
    let av = splitmix(3, N);
    let bv = splitmix(4, N);
    let a = to_array(&av);
    let b = to_array(&bv);

    // Naive reference.
    let expected = naive_negacyclic_mul(&a, &b);

    // NTT-based convolution: forward both, pointwise multiply,
    // inverse the result.
    let mut a_t = a;
    let mut b_t = b;
    negacyclic_forward(&mut a_t);
    negacyclic_forward(&mut b_t);
    let mut c_t = [0u32; N];
    for i in 0..N {
        c_t[i] = mul(a_t[i], b_t[i]);
    }
    negacyclic_inverse(&mut c_t);

    for i in 0..N {
        assert_eq!(c_t[i], expected[i], "coefficient {} mismatch", i);
    }
}

#[test]
fn psi_powers_are_distinct() {
    // The pre-twiddle table uses psi^i for i = 0..N-1. All N values
    // must be distinct.
    let mut set = std::collections::HashSet::new();
    let mut x = 1u32;
    for _ in 0..N {
        assert!(set.insert(x), "psi power repeated: {}", x);
        x = mul(x, PSI);
    }
}

#[test]
fn sampler_support_matches_tail_bound() {
    let s = GaussianSampler::default_ml_dsa();
    let support = s.support();
    // sigma = 3.2, tail = 6 sigma = 19.2, ceil = 20. Support is
    // [-20, 20], so 41 values.
    assert_eq!(support.len(), 41);
    assert_eq!(support[0], -20);
    assert_eq!(*support.last().unwrap(), 20);
}

#[test]
fn sampler_extreme_quantiles_are_bounded() {
    let s = GaussianSampler::default_ml_dsa();
    // u very close to 0 → leftmost value; u very close to 1 → rightmost.
    assert_eq!(s.sample_with_uniform(0.0), -20);
    assert_eq!(s.sample_with_uniform(1.0 - 1e-15), 20);
    // u = 0.5 → around 0 (the mode of the discrete Gaussian).
    let mid = s.sample_with_uniform(0.5);
    assert!(mid.abs() <= 1, "median sample was {}, expected near 0", mid);
}

#[test]
fn se3_identity() {
    let m = se3_exp_flat([0.0; 6]);
    let identity = [
        1.0, 0.0, 0.0, 0.0, //
        0.0, 1.0, 0.0, 0.0, //
        0.0, 0.0, 1.0, 0.0, //
        0.0, 0.0, 0.0, 1.0,
    ];
    for i in 0..16 {
        assert!((m[i] - identity[i]).abs() < 1e-12);
    }
}

#[test]
fn se3_translation_components() {
    let m = se3_exp_flat([1.5, -2.5, 3.5, 0.0, 0.0, 0.0]);
    assert!((m[3] - 1.5).abs() < 1e-9);
    assert!((m[7] + 2.5).abs() < 1e-9);
    assert!((m[11] - 3.5).abs() < 1e-9);
    // Rotation should be identity.
    assert!((m[0] - 1.0).abs() < 1e-12);
    assert!((m[5] - 1.0).abs() < 1e-12);
    assert!((m[10] - 1.0).abs() < 1e-12);
}

#[test]
fn se3_rotation_orthogonal() {
    // R * R^T should be the identity for any input.
    let m = se3_exp_flat([0.1, 0.2, 0.3, 0.7, -0.4, 0.2]);
    // Extract R.
    let r = [[m[0], m[1], m[2]], [m[4], m[5], m[6]], [m[8], m[9], m[10]]];
    // R * R^T.
    let mut rrt = [[0.0f64; 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            let mut s = 0.0;
            for k in 0..3 {
                s += r[i][k] * r[j][k];
            }
            rrt[i][j] = s;
        }
    }
    for i in 0..3 {
        for j in 0..3 {
            let expected = if i == j { 1.0 } else { 0.0 };
            assert!(
                (rrt[i][j] - expected).abs() < 1e-9,
                "R R^T [{},{}] = {}",
                i,
                j,
                rrt[i][j]
            );
        }
    }
}

#[test]
fn se3_rotation_determinant_is_one() {
    let m = se3_exp_flat([0.0, 0.0, 0.0, 0.3, -0.8, 0.5]);
    let r = [[m[0], m[1], m[2]], [m[4], m[5], m[6]], [m[8], m[9], m[10]]];
    let det = r[0][0] * (r[1][1] * r[2][2] - r[1][2] * r[2][1])
        - r[0][1] * (r[1][0] * r[2][2] - r[1][2] * r[2][0])
        + r[0][2] * (r[1][0] * r[2][1] - r[1][1] * r[2][0]);
    assert!((det - 1.0).abs() < 1e-9, "det(R) = {}", det);
}
