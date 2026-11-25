"""Traffic entropy and hardware-entropy handling (Sections 6.4.1, 6.4.3)."""
import hashlib, os
import numpy as np

def kl_divergence(p, q, eps=1e-12):
    p = np.asarray(p, float) + eps; q = np.asarray(q, float) + eps
    p /= p.sum(); q /= q.sum()
    return float(np.sum(p * np.log(p / q)))

def sigma_from_kl(kl, s_min=0.05, s_max=1.0, k=4.0, kl0=0.3):
    """Eq. (120): sigma(t) = Psi(D_KL). Psi is a sigmoid; kl0 = 0.3 matches the S1 threshold."""
    return s_min + (s_max - s_min) / (1 + np.exp(-k * (kl - kl0) / kl0))

class EntropySource:
    """Whitened entropy. Python cannot execute RDRAND/RDSEED, so we mix
    os.urandom (which on x86 Linux already folds in RDRAND) through SHA3.
    A seeded mode exists for deterministic tests only."""
    def __init__(self, seed=None):
        self.seed = seed; self.ctr = 0
        self.rng = np.random.default_rng(seed) if seed is not None else None

    def bytes(self, n):
        out = b""
        while len(out) < n:
            raw = (self.rng.bytes(32) if self.rng is not None else os.urandom(32))
            self.ctr += 1
            out += hashlib.sha3_256(raw + self.ctr.to_bytes(8, "big")).digest()
        return out[:n]

    def uniform(self, m):
        b = np.frombuffer(self.bytes(8 * m), dtype=np.uint64)
        return ((b >> np.uint64(11)).astype(float) + 0.5) / 2**53

    def normal(self, size):
        m = int(np.prod(size)); h = m // 2 + 1
        u = self.uniform(2 * h)
        r = np.sqrt(-2 * np.log(u[:h])); th = 2 * np.pi * u[h:2 * h]
        z = np.concatenate([r * np.cos(th), r * np.sin(th)])
        return z[:m].reshape(size)

def shannon_bits(data: bytes) -> float:
    c = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(float); p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())
