/*
 * c/reference/src/field.c
 *
 * Implementation of the finite-field arithmetic.
 *
 * We wrote the four arithmetic operations as straight-line code rather
 * than as macros because the compiler's inliner already handles the
 * static functions correctly, and macros would have made the code
 * harder to debug. The reference implementation is not on any hot
 * path; a fast implementation lives in rust/a3e_core/src/field.rs.
 */

#include "field.h"

uint32_t field_reduce(uint32_t a) {
    return a % FIELD_Q;
}

uint32_t field_add(uint32_t a, uint32_t b) {
    uint32_t s = a + b;
    if (s >= FIELD_Q) {
        s -= FIELD_Q;
    }
    return s;
}

uint32_t field_sub(uint32_t a, uint32_t b) {
    if (a >= b) {
        return a - b;
    }
    return FIELD_Q - (b - a);
}

uint32_t field_mul(uint32_t a, uint32_t b) {
    return (uint32_t)(((uint64_t)a * (uint64_t)b) % (uint64_t)FIELD_Q);
}

uint32_t field_neg(uint32_t a) {
    if (a == 0) {
        return 0;
    }
    return FIELD_Q - a;
}

uint32_t field_pow(uint32_t base, uint64_t exp) {
    uint32_t result = 1;
    uint32_t b = base % FIELD_Q;
    uint64_t e = exp;
    while (e > 0) {
        if (e & 1u) {
            result = field_mul(result, b);
        }
        b = field_mul(b, b);
        e >>= 1;
    }
    return result;
}

uint32_t field_inverse(uint32_t a) {
    /* Fermat: a^(Q - 2) mod Q. */
    return field_pow(a, (uint64_t)(FIELD_Q - 2u));
}
