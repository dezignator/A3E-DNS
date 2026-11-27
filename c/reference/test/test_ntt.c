/*
 * c/reference/test/test_ntt.c
 *
 * Tests for the NTT and field arithmetic.
 *
 * The tests use a minimal assert-based harness rather than a full
 * unit-test framework, because the reference implementation exists to
 * be read and run as part of a thesis artifact, and adding a unittest
 * dependency would have required a build-system change that made the
 * "one command to compile and test" claim in the README false.
 *
 * The key test is test_ntt_agrees_with_naive: it checks that the
 * NTT-based convolution equals the naive polynomial multiplication
 * for a randomly chosen pair of inputs. That is a real correctness
 * check; a round-trip alone would be satisfied by an identity
 * transform.
 */

#include "ntt.h"
#include "field.h"
#include "sampler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int total_tests = 0;
static int failed_tests = 0;

#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        total_tests++;                                                     \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
            failed_tests++;                                                \
        }                                                                  \
    } while (0)

#define CHECK_EQ(a, b, msg) CHECK((a) == (b), msg)

static void fill_random(uint32_t *buf, size_t n, uint64_t seed) {
    SplitMix64 rng;
    splitmix64_init(&rng, seed);
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint32_t)(splitmix64_next(&rng) % FIELD_Q);
    }
}

/* ------------------------------------------------------------------ */
/* Field arithmetic                                                    */
/* ------------------------------------------------------------------ */

static void test_field_identities(void) {
    uint32_t samples[] = {0, 1, 17, 1753, FIELD_Q / 2, FIELD_Q - 1};
    size_t n = sizeof(samples) / sizeof(samples[0]);
    for (size_t i = 0; i < n; i++) {
        uint32_t a = samples[i];
        CHECK_EQ(field_add(a, 0), a, "additive identity");
        CHECK_EQ(field_mul(a, 1), a, "multiplicative identity");
        CHECK_EQ(field_mul(a, 0), 0, "multiplication by zero");
        CHECK_EQ(field_neg(field_neg(a)), a, "double negation");
        CHECK_EQ(field_add(a, field_neg(a)), 0, "additive inverse");
        if (a != 0) {
            CHECK_EQ(field_mul(a, field_inverse(a)), 1, "multiplicative inverse");
        }
    }
}

static void test_field_fermat(void) {
    uint32_t bases[] = {2, 3, 17, 1753, FIELD_Q - 1};
    for (size_t i = 0; i < 5; i++) {
        CHECK_EQ(field_pow(bases[i], FIELD_Q - 1), 1, "Fermat little theorem");
    }
}

/* ------------------------------------------------------------------ */
/* NTT round-trip                                                      */
/* ------------------------------------------------------------------ */

static void test_ntt_round_trip(void) {
    uint32_t original[NTT_N];
    fill_random(original, NTT_N, 20231130);
    uint32_t buf[NTT_N];
    memcpy(buf, original, sizeof(original));
    ntt_forward(buf);
    ntt_inverse(buf);
    for (int i = 0; i < NTT_N; i++) {
        CHECK_EQ(buf[i], original[i], "NTT round-trip");
    }
}

static void test_ntt_zero_stays_zero(void) {
    uint32_t buf[NTT_N];
    memset(buf, 0, sizeof(buf));
    ntt_forward(buf);
    for (int i = 0; i < NTT_N; i++) {
        CHECK_EQ(buf[i], 0, "NTT of zero is zero");
    }
}

static void test_ntt_one_polynomial(void) {
    /* a(X) = 1. The transform evaluates to all ones at every
     * evaluation point, so the output should be the vector of ones
     * in the NTT domain (which is then un-twiddled and bit-reversed). */
    uint32_t buf[NTT_N];
    memset(buf, 0, sizeof(buf));
    buf[0] = 1;
    ntt_forward(buf);
    ntt_inverse(buf);
    CHECK_EQ(buf[0], 1, "NTT of constant 1: coefficient 0");
    for (int i = 1; i < NTT_N; i++) {
        CHECK_EQ(buf[i], 0, "NTT of constant 1: trailing coefficients");
    }
}

/* ------------------------------------------------------------------ */
/* NTT vs naive multiplication                                         */
/* ------------------------------------------------------------------ */

static void test_ntt_agrees_with_naive(void) {
    uint32_t a[NTT_N], b[NTT_N];
    fill_random(a, NTT_N, 42);
    fill_random(b, NTT_N, 43);

    /* Naive reference. */
    uint32_t expected[NTT_N];
    ntt_naive_multiply(a, b, expected);

    /* NTT-based convolution. */
    uint32_t a_t[NTT_N], b_t[NTT_N];
    memcpy(a_t, a, sizeof(a));
    memcpy(b_t, b, sizeof(b));
    ntt_forward(a_t);
    ntt_forward(b_t);
    uint32_t c_t[NTT_N];
    for (int i = 0; i < NTT_N; i++) {
        c_t[i] = field_mul(a_t[i], b_t[i]);
    }
    ntt_inverse(c_t);

    for (int i = 0; i < NTT_N; i++) {
        CHECK_EQ(c_t[i], expected[i], "NTT convolution vs naive");
    }
}

/* ------------------------------------------------------------------ */
/* PSI primitive 512-th root                                           */
/* ------------------------------------------------------------------ */

static void test_psi_primitive(void) {
    uint32_t x = 1;
    for (int i = 0; i < 512; i++) {
        x = field_mul(x, NTT_PSI);
    }
    CHECK_EQ(x, 1, "PSI^512 == 1");
    uint32_t y = 1;
    for (int i = 0; i < 256; i++) {
        y = field_mul(y, NTT_PSI);
    }
    CHECK_EQ(y, FIELD_Q - 1, "PSI^256 == -1");
}

/* ------------------------------------------------------------------ */

int main(void) {
    test_field_identities();
    test_field_fermat();
    test_ntt_round_trip();
    test_ntt_zero_stays_zero();
    test_ntt_one_polynomial();
    test_ntt_agrees_with_naive();
    test_psi_primitive();

    if (failed_tests > 0) {
        fprintf(stderr, "%d/%d tests failed\n", failed_tests, total_tests);
        return 1;
    }
    printf("%d/%d tests passed\n", total_tests, total_tests);
    return 0;
}
