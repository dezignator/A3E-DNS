"""Additively homomorphic RLWE scheme (BFV-style, add + plaintext-scalar only).

Chapter 6 uses homomorphic evaluation for three things: summing encrypted
counters, comparing against thresholds after decryption by the authorised
party, and scalar scaling. No ciphertext-ciphertext multiplication is
needed, so none is implemented.
"""
from dataclasses import dataclass
import numpy as np
from .ring import RingParams, negacyclic_mul
from .sampler import TableGaussianSampler

@dataclass
class Ciphertext:
    c0: np.ndarray; c1: np.ndarray; adds: int = 0

class RLWEAdditive:
    def __init__(self, params: RingParams, seed=0):
        self.p = params; self.rng = np.random.default_rng(seed)
        self.gs = TableGaussianSampler(params.sigma, seed=seed + 1)
        n, q = params.n, params.q
        self.s = self.rng.integers(-1, 2, n)                       # ternary secret
        a = self.rng.integers(0, q, n); e = self.gs.sample(n)
        self.pk = (np.mod(-negacyclic_mul(a, np.mod(self.s, q), q) + e, q), a)

    def encrypt(self, m):
        p = self.p; q = p.q; m = np.asarray(m, np.int64)
        assert m.shape == (p.n,) and m.min() >= 0 and m.max() < p.t
        u = self.rng.integers(-1, 2, p.n); b, a = self.pk
        c0 = np.mod(negacyclic_mul(b, np.mod(u, q), q) + self.gs.sample(p.n) + p.delta * m, q)
        c1 = np.mod(negacyclic_mul(a, np.mod(u, q), q) + self.gs.sample(p.n), q)
        return Ciphertext(c0, c1)

    def add(self, x, y): return Ciphertext((x.c0 + y.c0) % self.p.q, (x.c1 + y.c1) % self.p.q, x.adds + y.adds + 1)

    def scale(self, x, k): return Ciphertext((k * x.c0) % self.p.q, (k * x.c1) % self.p.q, x.adds)

    def phase(self, ct):
        q = self.p.q; v = np.mod(ct.c0 + negacyclic_mul(ct.c1, np.mod(self.s, q), q), q)
        return v

    def decrypt(self, ct):
        p = self.p; v = self.phase(ct)
        return np.mod(np.rint(v / p.delta).astype(np.int64), p.t)

    def noise(self, ct, m_expected):
        p = self.p; v = self.phase(ct).astype(np.int64)
        d = v - p.delta * np.asarray(m_expected, np.int64); d = (d + p.q // 2) % p.q - p.q // 2
        return int(np.abs(d).max())

    def noise_budget_bits(self, ct, m_expected):
        nz = max(self.noise(ct, m_expected), 1)
        return float(np.log2(self.p.delta / 2) - np.log2(nz))
