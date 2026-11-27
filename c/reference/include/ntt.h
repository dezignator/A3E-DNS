/*
 * c/reference/include/ntt.h
 *
 * Negacyclic Number Theoretic Transform over Z_Q[X]/(X^N + 1).
 *
 * The transform parameters match rust/a3e_core/src/ntt.rs:
 *
 *   N    = 256
 *   PSI  = 1753   (a primitive 512-th root of unity mod Q)
 *   Q    = 8380417
 *
 * The implementation uses the twist-then-cyclic algorithm:
 *
 *   1. pre-twiddle each coefficient by PSI^i,
 *   2. cyclic NTT with omega = PSI^2,
 *   3. the result evaluates the input at PSI^(2k+1) for k = 0..N-1.
 *
 * The inverse reverses the three steps. The two implementations must
 * agree coefficient-for-coefficient; the integration test in
 * c/reference/test/test_ntt.c checks that against the naive O(N^2)
 * multiplication, which is the ground truth neither implementation
 * could trivially satisfy without being correct.
 */

#ifndef A3E_REFERENCE_NTT_H
#define A3E_REFERENCE_NTT_H

#include <stdint.h>
#include "field.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NTT_N 256
#define NTT_PSI 1753u

/* Forward negacyclic NTT, in place. */
void ntt_forward(uint32_t *coeffs);

/* Inverse negacyclic NTT, in place. */
void ntt_inverse(uint32_t *coeffs);

/*
 * Naive negacyclic multiplication for reference and testing.
 *
 * Given a and b, writes a*b mod (X^N + 1) into out. This is O(N^2)
 * and is intended only for cross-checking the NTT-based path; a
 * production caller should always use the NTT.
 */
void ntt_naive_multiply(const uint32_t *a, const uint32_t *b, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* A3E_REFERENCE_NTT_H */
