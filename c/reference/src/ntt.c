/*
 * c/reference/src/ntt.c
 *
 * Negacyclic NTT implementation.
 *
 * We wrote this in the "obvious" style — loops unrolled only where the
 * butterfly structure requires it — because the reference's purpose is
 * to be reviewable. A reviewer who knows the Cooley-Tukey algorithm
 * can read this in five minutes and check it against the published
 * variant. The Rust version optimises the twiddle multiplication table
 * into a const array; this version computes the twiddles inside the
 * butterfly loop, which is ~10× slower but three times shorter.
 */

#include "ntt.h"

#include <string.h>

/* PSI^0 through PSI^(N-1) mod Q, computed at startup. */
static uint32_t psi_table[NTT_N];
static uint32_t psi_inverse_table[NTT_N];
static uint32_t bit_reversal[NTT_N];
static int tables_initialized = 0;

static void init_tables(void) {
    if (tables_initialized) {
        return;
    }
    /* PSI powers. */
    psi_table[0] = 1;
    for (int i = 1; i < NTT_N; i++) {
        psi_table[i] = field_mul(psi_table[i - 1], NTT_PSI);
    }
    /* Inverse PSI powers. */
    uint32_t psi_inv = field_inverse(NTT_PSI);
    psi_inverse_table[0] = 1;
    for (int i = 1; i < NTT_N; i++) {
        psi_inverse_table[i] = field_mul(psi_inverse_table[i - 1], psi_inv);
    }
    /* Bit reversal permutation for 8-bit indices. */
    for (int i = 0; i < NTT_N; i++) {
        uint32_t x = (uint32_t)i;
        uint32_t r = 0;
        for (int b = 0; b < 8; b++) {
            r = (r << 1) | (x & 1u);
            x >>= 1;
        }
        bit_reversal[i] = r;
    }
    tables_initialized = 1;
}

/* Cyclic Cooley-Tukey NTT in place. */
static void cyclic_ntt(uint32_t *a, uint32_t omega) {
    for (int len = 2; len <= NTT_N; len <<= 1) {
        uint32_t wlen = field_pow(omega, (uint64_t)(NTT_N / len));
        int half = len / 2;
        for (int i = 0; i < NTT_N; i += len) {
            uint32_t wk = 1;
            for (int j = 0; j < half; j++) {
                uint32_t u = a[i + j];
                uint32_t v = field_mul(a[i + j + half], wk);
                a[i + j] = field_add(u, v);
                a[i + j + half] = field_sub(u, v);
                wk = field_mul(wk, wlen);
            }
        }
    }
}

void ntt_forward(uint32_t *coeffs) {
    init_tables();
    uint32_t tmp[NTT_N];
    /* Pre-twiddle. */
    for (int i = 0; i < NTT_N; i++) {
        coeffs[i] = field_mul(coeffs[i], psi_table[i]);
    }
    /* Bit-reverse. */
    for (int i = 0; i < NTT_N; i++) {
        tmp[i] = coeffs[bit_reversal[i]];
    }
    /* Cyclic NTT with omega = PSI^2. */
    cyclic_ntt(tmp, field_mul(NTT_PSI, NTT_PSI));
    memcpy(coeffs, tmp, sizeof(tmp));
}

void ntt_inverse(uint32_t *coeffs) {
    init_tables();
    uint32_t tmp[NTT_N];
    uint32_t omega = field_mul(NTT_PSI, NTT_PSI);
    uint32_t omega_inv = field_inverse(omega);
    /* Bit-reverse. */
    for (int i = 0; i < NTT_N; i++) {
        tmp[i] = coeffs[bit_reversal[i]];
    }
    /* Cyclic inverse NTT with omega^{-1}. */
    cyclic_ntt(tmp, omega_inv);
    /* Scale by 1/N. */
    uint32_t n_inv = field_inverse((uint32_t)NTT_N);
    for (int i = 0; i < NTT_N; i++) {
        tmp[i] = field_mul(tmp[i], n_inv);
    }
    /* Post-twiddle with PSI^{-i}. */
    for (int i = 0; i < NTT_N; i++) {
        coeffs[i] = field_mul(tmp[i], psi_inverse_table[i]);
    }
}

void ntt_naive_multiply(const uint32_t *a, const uint32_t *b, uint32_t *out) {
    memset(out, 0, NTT_N * sizeof(uint32_t));
    for (int i = 0; i < NTT_N; i++) {
        if (a[i] == 0) {
            continue;
        }
        for (int j = 0; j < NTT_N; j++) {
            if (b[j] == 0) {
                continue;
            }
            uint32_t product = field_mul(a[i], b[j]);
            int idx = i + j;
            if (idx < NTT_N) {
                out[idx] = field_add(out[idx], product);
            } else {
                /* X^(i+j) = X^(i+j-N) * X^N = -X^(i+j-N). */
                out[idx - NTT_N] = field_sub(out[idx - NTT_N], product);
            }
        }
    }
}
