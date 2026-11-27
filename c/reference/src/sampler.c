/*
 * c/reference/src/sampler.c
 *
 * CDT Gaussian sampler and SplitMix64 RNG.
 *
 * The SplitMix64 algorithm is the one described in Steele et al.,
 * "Fast Splittable Pseudorandom Number Generators" (OOPSLA 2014), and
 * is identical to the Rust implementation in a3e_core::sampler. The
 * CDT is built once at sampler_init and held in the sampler struct so
 * that sample_many does not rebuild it per draw; the reference
 * implementation could have rebuilt it each call but that would have
 * made the tests ~100× slower and obscured the actual sampling logic.
 */

#include "sampler.h"

#include <math.h>
#include <string.h>

void splitmix64_init(SplitMix64 *rng, uint64_t seed) {
    rng->state = seed;
}

uint64_t splitmix64_next(SplitMix64 *rng) {
    rng->state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

double splitmix64_next_f64(SplitMix64 *rng) {
    /* 53-bit mantissa; the shift discards the low bits that would
     * cause bias in the (0, 1) uniform conversion. */
    uint64_t v = splitmix64_next(rng);
    return (double)(v >> 11) * (1.0 / (double)(1ULL << 53));
}

void sampler_init(GaussianSampler *s) {
    int bound = (int)ceil(SAMPLER_TAIL * SAMPLER_SIGMA);  /* 20 */
    /* Build support. */
    int idx = 0;
    for (int x = -bound; x <= bound; x++) {
        s->support[idx++] = x;
    }
    /* Compute unnormalised weights. */
    double weights[SAMPLER_SUPPORT_SIZE];
    double total = 0.0;
    for (int i = 0; i < SAMPLER_SUPPORT_SIZE; i++) {
        double t = (double)s->support[i] / SAMPLER_SIGMA;
        double w = exp(-0.5 * t * t);
        weights[i] = w;
        total += w;
    }
    /* Cumulative sum. */
    double cum = 0.0;
    for (int i = 0; i < SAMPLER_SUPPORT_SIZE; i++) {
        cum += weights[i] / total;
        s->cdt[i] = cum;
    }
    /* Force the last value to 1.0 so that u == 1 - eps is well defined. */
    s->cdt[SAMPLER_SUPPORT_SIZE - 1] = 1.0;
}

int32_t sampler_sample_with_uniform(const GaussianSampler *s, double u) {
    for (int i = 0; i < SAMPLER_SUPPORT_SIZE; i++) {
        if (u < s->cdt[i]) {
            return s->support[i];
        }
    }
    return s->support[SAMPLER_SUPPORT_SIZE - 1];
}

int32_t sampler_sample(const GaussianSampler *s, SplitMix64 *rng) {
    return sampler_sample_with_uniform(s, splitmix64_next_f64(rng));
}

void sampler_sample_many(
    const GaussianSampler *s,
    SplitMix64 *rng,
    int32_t *out,
    size_t n
) {
    for (size_t i = 0; i < n; i++) {
        out[i] = sampler_sample(s, rng);
    }
}
