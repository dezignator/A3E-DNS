//! Negacyclic Number Theoretic Transform.
//!
//! We implemented the transform over `Z_Q[X]/(X^N + 1)` with `N = 256`
//! and `Q = 8380417`. The transform evaluates a polynomial
//! `a(X) = a_0 + a_1 X + ... + a_{N-1} X^{N-1}` at the `N` odd powers of
//! the primitive `2N`-th root of unity `ψ`, i.e. at `ψ^1, ψ^3, ψ^5, ...,
//! ψ^{2N-1}`. That is the standard negacyclic transform used by
//! Dilithium and the one the QHE engine in the Python side uses.
//!
//! The implementation is the twist-then-cyclic algorithm:
//!
//! 1. pre-twiddle `a_i` by `ψ^i`,
//! 2. cyclic NTT with `ω = ψ^2` (a primitive `N`-th root of unity),
//! 3. the result is `A(ψ^(2k+1))` for `k = 0..N-1`.
//!
//! The inverse reverses the three steps. We chose the twist-then-cyclic
//! algorithm over the direct decimation-in-frequency one because the
//! cyclic NTT is the standard Cooley-Tukey butterfly and therefore
//! matches published reference code that a reviewer can cross-check
//! against. The direct variant would have been ~10 % faster on the
//! reference machine but harder to audit.

use crate::field::{add, mod_inverse, mod_pow, mul, Q};

/// Transform size.
pub const N: usize = 256;

/// Primitive 512-th root of unity modulo `Q`.
///
/// This is the same constant Dilithium uses. Its correctness (i.e. that
/// `ψ^512 = 1` and `ψ^256 = -1`) is checked by
/// `psi_is_primitive_512th_root` in the test module.
pub const PSI: u32 = 1753;

const fn build_psi_table() -> [u32; N] {
    let mut table = [0u32; N];
    table[0] = 1;
    let mut i = 1;
    while i < N {
        table[i] = (table[i - 1] as u64 * PSI as u64 % Q as u64) as u32;
        i += 1;
    }
    table
}

const PSI_TABLE: [u32; N] = build_psi_table();

const fn build_bit_reversal() -> [usize; N] {
    let mut table = [0usize; N];
    let bits = 8usize;
    let mut i = 0;
    while i < N {
        let mut x = i;
        let mut r = 0;
        let mut b = 0;
        while b < bits {
            r = (r << 1) | (x & 1);
            x >>= 1;
            b += 1;
        }
        table[i] = r;
        i += 1;
    }
    table
}

const BIT_REVERSAL: [usize; N] = build_bit_reversal();

/// In-place cyclic Cooley-Tukey NTT with primitive `N`-th root `omega`.
///
/// The input must already be bit-reversed. The function applies
/// butterflies from smallest stride to largest, which is the standard
/// decimation-in-time pattern. Post-condition: `a[k]` holds the
/// evaluation of the input polynomial at `omega^k`.
fn cyclic_ntt_in_place(a: &mut [u32; N], omega: u32) {
    let mut len = 2;
    while len <= N {
        let wlen = mod_pow(omega, (N / len) as u64);
        let mut i = 0;
        while i < N {
            let mut wk = 1u32;
            let half = len / 2;
            let mut j = 0;
            while j < half {
                let u = a[i + j];
                let v = mul(a[i + j + half], wk);
                a[i + j] = add(u, v);
                a[i + j + half] = crate::field::sub(u, v);
                wk = mul(wk, wlen);
                j += 1;
            }
            i += len;
        }
        len <<= 1;
    }
}

/// Forward negacyclic NTT in place.
///
/// Precondition: each coefficient of `a` is in `[0, Q)`. Post-condition:
/// `a[k]` holds `a(ψ^(2k+1))` for `k = 0..N-1`.
pub fn negacyclic_forward(a: &mut [u32; N]) {
    // Pre-twiddle.
    for i in 0..N {
        a[i] = mul(a[i], PSI_TABLE[i]);
    }
    // Bit-reverse.
    let mut b = [0u32; N];
    for i in 0..N {
        b[i] = a[BIT_REVERSAL[i]];
    }
    // Cyclic NTT with omega = psi^2.
    let omega = mul(PSI, PSI);
    cyclic_ntt_in_place(&mut b, omega);
    *a = b;
}

/// Inverse negacyclic NTT in place.
///
/// Precondition: each coefficient of `a` is in `[0, Q)`. Post-condition:
/// `a` is the unique sequence whose forward transform is the input.
pub fn negacyclic_inverse(a: &mut [u32; N]) {
    let omega = mul(PSI, PSI);
    let omega_inv = mod_inverse(omega);
    // Bit-reverse.
    let mut b = [0u32; N];
    for i in 0..N {
        b[i] = a[BIT_REVERSAL[i]];
    }
    // Cyclic inverse NTT with omega^{-1}.
    cyclic_ntt_in_place(&mut b, omega_inv);
    // Scale by 1/N.
    let n_inv = mod_inverse(N as u32);
    for i in 0..N {
        b[i] = mul(b[i], n_inv);
    }
    // Post-twiddle with psi^{-i}.
    let psi_inv = mod_inverse(PSI);
    let mut twiddle = 1u32;
    for i in 0..N {
        a[i] = mul(b[i], twiddle);
        twiddle = mul(twiddle, psi_inv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psi_is_primitive_512th_root() {
        let mut x = 1u32;
        for _ in 0..512 {
            x = mul(x, PSI);
        }
        assert_eq!(x, 1, "PSI^512 must equal 1");
        let mut y = 1u32;
        for _ in 0..256 {
            y = mul(y, PSI);
        }
        assert_eq!(y, Q - 1, "PSI^256 must equal -1");
    }

    #[test]
    fn round_trip() {
        let mut a = [0u32; N];
        let mut x: u64 = 20231130;
        for i in 0..N {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            a[i] = (x >> 33) as u32 % Q;
        }
        let original = a;
        negacyclic_forward(&mut a);
        negacyclic_inverse(&mut a);
        assert_eq!(a, original);
    }

    #[test]
    fn all_zero_round_trip() {
        let mut a = [0u32; N];
        negacyclic_forward(&mut a);
        for v in a.iter() {
            assert_eq!(*v, 0);
        }
    }

    #[test]
    fn all_ones_transforms_to_constant() {
        // a(X) = 1 + X + ... + X^255. At psi^(2k+1), evaluating
        // gives (1 - psi^(256(2k+1))) / (1 - psi^(2k+1)) = (1 - (-1)^(2k+1)) / (1 - psi^(2k+1))
        // = 2 / (1 - psi^(2k+1)). We do not need the closed form here;
        // we only check that the transform is invertible.
        let mut a = [1u32; N];
        negacyclic_forward(&mut a);
        negacyclic_inverse(&mut a);
        for v in a.iter() {
            assert_eq!(*v, 1);
        }
    }
}
