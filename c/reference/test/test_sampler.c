/*
 * c/reference/test/test_sampler.c
 *
 * Tests for the CDT sampler and SplitMix64 RNG.
 *
 * The moment test uses 100,000 samples and checks that the empirical
 * mean is within 0.05 of 0 and the empirical variance is within 0.10
 * of sigma^2. Those tolerances are loose enough that the test passes
 * reliably on any correct implementation and tight enough that a bug
 * in the CDT construction or in the RNG conversion would fail.
 *
 * The reproducibility test checks that two generators seeded
 * identically produce identical output for 100 draws. That is the
 * property the Rust implementation relies on to make cross-checks
 * reproducible, so it is worth asserting explicitly.
 */

#include "sampler.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

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

/* ------------------------------------------------------------------ */
/* CDT structural properties                                           */
/* ------------------------------------------------------------------ */

static void test_cdt_monotone(void) {
    GaussianSampler s;
    sampler_init(&s);
    for (int i = 1; i < SAMPLER_SUPPORT_SIZE; i++) {
        CHECK(s.cdt[i] >= s.cdt[i - 1], "CDT is monotone non-decreasing");
    }
    CHECK(fabs(s.cdt[SAMPLER_SUPPORT_SIZE - 1] - 1.0) < 1e-12,
          "last CDT value is 1.0");
}

static void test_support_symmetry(void) {
    GaussianSampler s;
    sampler_init(&s);
    int mid = SAMPLER_SUPPORT_SIZE / 2;
    for (int i = 0; i < mid; i++) {
        int32_t mirror = s.support[SAMPLER_SUPPORT_SIZE - 1 - i];
        CHECK_EQ(s.support[i], -mirror, "support is symmetric about 0");
    }
    CHECK_EQ(s.support[mid], 0, "support midpoint is 0");
}

/* ------------------------------------------------------------------ */
/* Sampling boundaries                                                 */
/* ------------------------------------------------------------------ */

static void test_extreme_quantiles(void) {
    GaussianSampler s;
    sampler_init(&s);
    CHECK_EQ(sampler_sample_with_uniform(&s, 0.0), s.support[0],
             "u=0 returns leftmost support value");
    CHECK_EQ(
        sampler_sample_with_uniform(&s, 1.0 - 1e-12),
        s.support[SAMPLER_SUPPORT_SIZE - 1],
        "u near 1 returns rightmost support value"
    );
    int32_t mid = sampler_sample_with_uniform(&s, 0.5);
    CHECK(mid >= -1 && mid <= 1, "u=0.5 returns near-zero value");
}

/* ------------------------------------------------------------------ */
/* Moments                                                             */
/* ------------------------------------------------------------------ */

static void test_sampler_moments(void) {
    GaussianSampler s;
    sampler_init(&s);
    SplitMix64 rng;
    splitmix64_init(&rng, 20231130);
    const int n = 100000;
    int32_t *samples = malloc(n * sizeof(int32_t));
    sampler_sample_many(&s, &rng, samples, n);
    double sum = 0.0, sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double v = (double)samples[i];
        sum += v;
        sum_sq += v * v;
    }
    double mean = sum / n;
    double var = sum_sq / n - mean * mean;
    CHECK(fabs(mean) < 0.05, "empirical mean close to 0");
    CHECK(fabs(var - 3.2 * 3.2) < 0.10, "empirical variance close to sigma^2");
    free(samples);
}

/* ------------------------------------------------------------------ */
/* RNG reproducibility                                                 */
/* ------------------------------------------------------------------ */

static void test_rng_reproducible(void) {
    SplitMix64 a, b;
    splitmix64_init(&a, 42);
    splitmix64_init(&b, 42);
    for (int i = 0; i < 100; i++) {
        CHECK(splitmix64_next(&a) == splitmix64_next(&b),
              "SplitMix64 reproducible");
    }
}

/* ------------------------------------------------------------------ */

int main(void) {
    test_cdt_monotone();
    test_support_symmetry();
    test_extreme_quantiles();
    test_sampler_moments();
    test_rng_reproducible();

    if (failed_tests > 0) {
        fprintf(stderr, "%d/%d tests failed\n", failed_tests, total_tests);
        return 1;
    }
    printf("%d/%d tests passed\n", total_tests, total_tests);
    return 0;
}
