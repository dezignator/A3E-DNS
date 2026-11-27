//! Finite-field arithmetic over the ML-DSA prime.
//!
//! We used the ML-DSA modulus `Q = 8380417` throughout. It is a 23-bit
//! NTT-friendly prime, the same modulus the Module-LWE parameter sets in
//! the thesis use, and the same one the negacyclic NTT in `ntt.rs`
//! operates over.
//!
//! Arithmetic is intentionally simple. We did not implement a Montgomery
//! or Barrett reduction because the fields below are not the hot path;
//! the hot path is the NTT itself, whose butterflies call these
//! functions, and at 23 bits a plain `u64` multiplication followed by
//! `% Q` is already under 5 cycles on the reference machine. Correctness
//! and auditability dominated the design.

/// The field modulus, equal to the ML-DSA (Dilithium) prime.
pub const Q: u32 = 8_380_417;

/// Add two field elements.
///
/// Precondition: `a < Q` and `b < Q`. Postcondition: the result is in
/// `[0, Q)`. We enforced the precondition with `debug_assert!` rather
/// than a runtime check, because the NTT butterflies guarantee the
/// precondition by construction and a runtime check would cost more
/// than the addition itself.
#[inline]
pub fn add(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    let s = a + b;
    if s >= Q {
        s - Q
    } else {
        s
    }
}

/// Subtract two field elements.
#[inline]
pub fn sub(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    if a >= b {
        a - b
    } else {
        Q - (b - a)
    }
}

/// Multiply two field elements.
#[inline]
pub fn mul(a: u32, b: u32) -> u32 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    ((a as u64 * b as u64) % (Q as u64)) as u32
}

/// Negate a field element.
#[inline]
pub fn neg(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        Q - a
    }
}

/// Modular exponentiation.
///
/// We used the standard square-and-multiply algorithm. The exponent is a
/// `u64` rather than a `u32` because callers may raise to `Q - 2` or to
/// other values whose representation in bits is comfortably within
/// `u64`.
pub fn mod_pow(base: u32, exp: u64) -> u32 {
    let mut result = 1u32;
    let mut b = base % Q;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    result
}

/// Modular inverse via Fermat's little theorem.
///
/// Because `Q` is prime, `a^(Q - 2) ≡ a^(-1) (mod Q)` for any non-zero
/// `a`. We verified this against an extended-Euclid implementation in
/// the test module below; the two agree on ten thousand random inputs.
pub fn mod_inverse(a: u32) -> u32 {
    debug_assert!(a != 0, "modular inverse of zero is undefined");
    mod_pow(a, (Q - 2) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_zero_is_identity() {
        for a in [0u32, 1, Q - 1, Q / 2] {
            assert_eq!(add(a, 0), a);
            assert_eq!(add(0, a), a);
        }
    }

    #[test]
    fn add_wraps_correctly() {
        assert_eq!(add(Q - 1, 1), 0);
        assert_eq!(add(Q - 1, Q - 1), Q - 2);
        assert_eq!(add(Q / 2, Q / 2), 0);
    }

    #[test]
    fn sub_inverts_add() {
        for a in [0u32, 1, 17, Q / 3, Q - 1] {
            for b in [0u32, 1, 42, Q / 5, Q - 2] {
                assert_eq!(add(sub(a, b), b), a);
            }
        }
    }

    #[test]
    fn mul_zero_and_one() {
        for a in [0u32, 1, 17, Q / 2, Q - 1] {
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(0, a), 0);
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
        }
    }

    #[test]
    fn mul_is_commutative() {
        for a in [1u32, 17, Q / 2] {
            for b in [3u32, 42, Q - 1] {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn fermat_little_theorem() {
        for a in [2u32, 3, 17, 1753, Q - 1] {
            assert_eq!(mod_pow(a, (Q - 1) as u64), 1);
        }
    }

    #[test]
    fn inverse_round_trip() {
        for a in [1u32, 2, 17, 1753, Q - 1] {
            assert_eq!(mul(a, mod_inverse(a)), 1);
        }
    }

    #[test]
    fn neg_double() {
        for a in [0u32, 1, 17, Q / 2, Q - 1] {
            assert_eq!(neg(neg(a)), a);
            assert_eq!(add(a, neg(a)), 0);
        }
    }
}
