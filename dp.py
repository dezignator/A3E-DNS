"""Differential-privacy accounting (Section 6.6.5).

Gaussian mechanism with L2 sensitivity = clip norm c; per-round noise std
= sigma * c. Composition via Renyi DP: eps_RDP(alpha) = T * alpha / (2 sigma^2),
converted to (eps, delta) by  eps = min_alpha [ eps_RDP(alpha) + log(1/delta)/(alpha-1) ].
Sub-sampling amplification is NOT used, which makes the reported eps an
upper bound for the full-participation setting.
"""
import numpy as np

class GaussianRDPAccountant:
    def __init__(self, sigma, delta=1e-5): self.sigma = sigma; self.delta = delta; self.T = 0
    def step(self, n=1): self.T += n
    def epsilon(self, T=None):
        T = self.T if T is None else T
        a = np.concatenate([np.linspace(1.01, 10, 400), np.linspace(10, 512, 800)])
        return float(np.min(T * a / (2 * self.sigma**2) + np.log(1 / self.delta) / (a - 1)))

def calibrate_sigma(eps_target, T, delta=1e-5):
    lo, hi = 0.05, 1e4
    for _ in range(80):
        mid = np.sqrt(lo * hi)
        if GaussianRDPAccountant(mid, delta).epsilon(T) > eps_target: lo = mid
        else: hi = mid
    return hi
