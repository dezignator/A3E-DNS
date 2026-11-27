/*
 * c/reference/include/field.h
 *
 * Finite-field arithmetic over the ML-DSA prime Q = 8380417.
 *
 * We used this header for the reference implementation of the field
 * arithmetic that the NTT depends on. The constants and the semantics
 * match rust/a3e_core/src/field.rs exactly, so that the two
 * implementations can be cross-checked against each other.
 *
 * Every function below assumes its inputs are already reduced into
 * [0, Q). Callers that need to reduce first should call
 * field_reduce() explicitly; that made the reference implementation
 * easier to reason about than an implicit-reduction design, and the
 * extra function call is negligible for a reference whose purpose is
 * correctness rather than speed.
 */

#ifndef A3E_REFERENCE_FIELD_H
#define A3E_REFERENCE_FIELD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ML-DSA prime. */
#define FIELD_Q 8380417u

/* Add two field elements. Precondition: a < Q, b < Q. */
uint32_t field_add(uint32_t a, uint32_t b);

/* Subtract two field elements. Precondition: a < Q, b < Q. */
uint32_t field_sub(uint32_t a, uint32_t b);

/* Multiply two field elements. Precondition: a < Q, b < Q. */
uint32_t field_mul(uint32_t a, uint32_t b);

/* Additive inverse. Precondition: a < Q. */
uint32_t field_neg(uint32_t a);

/* Modular exponentiation. */
uint32_t field_pow(uint32_t base, uint64_t exp);

/* Modular inverse via Fermat's little theorem. Precondition: a != 0. */
uint32_t field_inverse(uint32_t a);

/*
 * Reduce an arbitrary uint32_t into [0, Q).
 *
 * We included this because the Fermat inverse and the mod-pow routine
 * both accept inputs that may be at or above Q after a caller-side
 * computation; silently truncating them to [0, Q) would have hidden
 * bugs, so the reduction is explicit.
 */
uint32_t field_reduce(uint32_t a);

#ifdef __cplusplus
}
#endif

#endif /* A3E_REFERENCE_FIELD_H */
