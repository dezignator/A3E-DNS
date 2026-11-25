"""Discrete Gaussian samplers (Section 6.5.2).

Chapter 6 describes a Ziggurat-based sampler with pre-computed tables.
We implement the table-driven idea in its simplest exact form (a
cumulative distribution table, CDT) and a rejection baseline. The
ziggurat layering itself is not reproduced; the claim "47 % lower
latency" in the thesis refers to the C implementation and is not
re-measured here.
"""
import numpy as np

class TableGaussianSampler:
    def __init__(self, sigma=1.58, tail=8.0, seed=None):
        self.sigma = sigma; B = int(np.ceil(tail * sigma))
        xs = np.arange(-B, B + 1); p = np.exp(-xs**2 / (2 * sigma**2)); p /= p.sum()
        self.xs = xs; self.cdf = np.cumsum(p); self.rng = np.random.default_rng(seed)

    def sample(self, size):
        u = self.rng.random(size)
        return self.xs[np.minimum(np.searchsorted(self.cdf, u), len(self.xs) - 1)].astype(np.int64)

class RejectionGaussianSampler:
    def __init__(self, sigma=1.58, tail=8.0, seed=None):
        self.sigma = sigma; self.B = int(np.ceil(tail * sigma)); self.rng = np.random.default_rng(seed)

    def sample(self, size):
        n = int(np.prod(size)); out = np.empty(0, np.int64)
        while len(out) < n:
            x = self.rng.integers(-self.B, self.B + 1, size=2 * n)
            keep = self.rng.random(2 * n) < np.exp(-x**2 / (2 * self.sigma**2))
            out = np.concatenate([out, x[keep]])
        return out[:n].reshape(size)
