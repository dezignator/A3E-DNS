/*
 * c/reference/include/sampler.h
 *
 * CDT Gaussian sampler with the ML-DSA parameter set.
 *
 * We used sigma = 3.2 and tail = 6*sigma = 19.2, rounded up to 20, so
 * the support is [-20, 20] inclusive (41 values). The parameters match
 * rust/a3e_core/src/sampler.rs and
 * extended_experimentation.qhe.quantum_safe_homomorphic_engine.py.
 *
 * The RNG is SplitMix64, identical to the Rust version's. Both are
 * seeded from the same 64-bit input, so the two implementations
 * produce identical sample streams given identical seeds; the
 * integration test in c/reference/test/test_sampler.c checks this
 * against a fixed set of expected values.
 */

#ifndef A3E_REFERENCE_SAMPLER_H
#define A3E_REFERENCE_SAMPLER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SAMPLER_SUPPORT_SIZE 41
#define SAMPLER_SIGMA 3.2
#define SAMPLER_TAIL 6.0

typedef struct {
    uint64_t state;
} SplitMix64;

void splitmix64_init(SplitMix64 *rng, uint64_t seed);
uint64_t splitmix64_next(SplitMix64 *rng);
double splitmix64_next_f64(SplitMix64 *rng);

/*
 * The CDT sampler.
 *
 * We stored the support explicitly rather than computing it in
 * sample_with_uniform so that a caller can inspect the support without
 * a helper. The CDT values were precomputed by sampler_init and are
 * guaranteed monotone non-decreasing with cdt[last] == 1.0.
 */
typedef struct {
    int32_t support[SAMPLER_SUPPORT_SIZE];
    double cdt[SAMPLER_SUPPORT_SIZE];
} GaussianSampler;

void sampler_init(GaussianSampler *s);
int32_t sampler_sample_with_uniform(const GaussianSampler *s, double u);
int32_t sampler_sample(const GaussianSampler *s, SplitMix64 *rng);
void sampler_sample_many(
    const GaussianSampler *s,
    SplitMix64 *rng,
    int32_t *out,
    size_t n
);

#ifdef __cplusplus
}
#endif

#endif /* A3E_REFERENCE_SAMPLER_H */
