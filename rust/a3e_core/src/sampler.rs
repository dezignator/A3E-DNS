//! CDT Gaussian sampler with a dependency-free RNG.
//!
//! We implemented the sampler the QHE engine uses for its error
//! polynomial. The distribution is a discrete Gaussian with `σ = 3.2`
//! and a tail bound of `6σ`, which is the parameter set the thesis
//! documents. The sampler uses the cumulative-distribution-table (CDT)
//! method rather than rejection sampling because the CDT has a bounded
//! runtime: the maximum number of table lookups is the support size,
//! regardless of the input.
//!
//! The RNG is SplitMix64. We chose it because it is short, stateful,
//! has excellent statistical properties, and is trivial to seed
//! deterministically. A production deployment would substitute
//! ChaCha20 or a system entropy source; the extension module exposes
//! the seeding hook so that a Python caller can pass either a fixed
//! seed for reproducibility or an entropy-derived seed for deployment.

/// The fixed-point RNG.
///
/// SplitMix64 as described in Steele et al., "Fast Splittable
/// Pseudorandom Number Generators" (2014). The output is `u64`; the
/// `next_f64` method converts to a uniform `f64` in `[0, 1)`.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Construct a generator from a `u64` seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advance and return a `u64`.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Return a uniform `f64` in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / ((1u64 << 53) as f64))
    }
}

/// CDT Gaussian sampler.
pub struct GaussianSampler {
    support: Vec<i32>,
    cdt: Vec<f64>,
}

impl GaussianSampler {
    /// Construct a sampler with the given `sigma` and `tail` in units of
    /// `sigma`.
    pub fn new(sigma: f64, tail: f64) -> Self {
        let bound = (tail * sigma).ceil() as i32;
        let support: Vec<i32> = (-bound..=bound).collect();
        let weights: Vec<f64> = support
            .iter()
            .map(|&x| {
                let t = (x as f64) / sigma;
                (-0.5 * t * t).exp()
            })
            .collect();
        let total: f64 = weights.iter().sum();
        let mut cdt = Vec::with_capacity(support.len());
        let mut cum = 0.0;
        for w in weights {
            cum += w / total;
            cdt.push(cum);
        }
        if let Some(last) = cdt.last_mut() {
            *last = 1.0;
        }
        Self { support, cdt }
    }

    /// The ML-DSA parameter set: `σ = 3.2`, `tail = 6σ`.
    pub fn default_ml_dsa() -> Self {
        Self::new(3.2, 6.0)
    }

    /// The support values, from `-bound` to `+bound` inclusive.
    pub fn support(&self) -> &[i32] {
        &self.support
    }

    /// The cumulative distribution table.
    pub fn cdt(&self) -> &[f64] {
        &self.cdt
    }

    /// Sample from a uniform value `u` in `[0, 1)`.
    pub fn sample_with_uniform(&self, u: f64) -> i32 {
        for (i, &c) in self.cdt.iter().enumerate() {
            if u < c {
                return self.support[i];
            }
        }
        *self.support.last().unwrap_or(&0)
    }

    /// Sample from the RNG.
    pub fn sample(&self, rng: &mut SplitMix64) -> i32 {
        self.sample_with_uniform(rng.next_f64())
    }

    /// Sample `n` values from the RNG.
    pub fn sample_many(&self, rng: &mut SplitMix64, n: usize) -> Vec<i32> {
        (0..n).map(|_| self.sample(rng)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdt_is_monotone_and_ends_at_one() {
        let s = GaussianSampler::default_ml_dsa();
        let cdt = s.cdt();
        for w in cdt.windows(2) {
            assert!(w[0] <= w[1], "CDT must be monotone non-decreasing");
        }
        assert!((cdt.last().unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn support_is_symmetric() {
        let s = GaussianSampler::default_ml_dsa();
        let support = s.support();
        assert_eq!(support.len() % 2, 1);
        let mid = support.len() / 2;
        for i in 0..mid {
            assert_eq!(support[i], -support[support.len() - 1 - i]);
        }
        assert_eq!(support[mid], 0);
    }

    #[test]
    fn sample_zero_uniform_returns_leftmost() {
        let s = GaussianSampler::default_ml_dsa();
        assert_eq!(s.sample_with_uniform(0.0), *s.support().first().unwrap());
    }

    #[test]
    fn sample_near_one_returns_rightmost() {
        let s = GaussianSampler::default_ml_dsa();
        assert_eq!(
            s.sample_with_uniform(1.0 - 1e-12),
            *s.support().last().unwrap()
        );
    }

    #[test]
    fn empirical_mean_and_variance() {
        let s = GaussianSampler::default_ml_dsa();
        let mut rng = SplitMix64::new(20231130);
        let n = 100_000;
        let samples = s.sample_many(&mut rng, n);
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let var: f64 = samples
            .iter()
            .map(|&x| {
                let d = x as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / (n as f64 - 1.0);
        assert!(mean.abs() < 0.05, "empirical mean {} too far from 0", mean);
        assert!(
            (var - 3.2 * 3.2).abs() < 0.1,
            "empirical variance {} too far from 10.24",
            var
        );
    }

    #[test]
    fn rng_is_reproducible() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
