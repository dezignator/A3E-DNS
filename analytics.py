"""Encrypted traffic analytics (Section 6.5.3 - 6.5.5)."""
import numpy as np
from .scheme import RLWEAdditive

def chi_square_from_counts(obs, expected):
    obs = np.asarray(obs, float); exp = np.asarray(expected, float); exp = exp * obs.sum() / exp.sum()
    m = exp > 0
    return float(((obs[m] - exp[m])**2 / exp[m]).sum())

def select_features(X, y, k):
    """Selective-operation stage: keep the k features with largest standardised class separation."""
    mu1, mu0 = X[y == 1].mean(0), X[y == 0].mean(0); sd = X.std(0) + 1e-9
    score = np.abs(mu1 - mu0) / sd
    return np.argsort(-score)[:k]

class EncryptedHistogram:
    """Each reporter encrypts a bin-count vector; the analyzer adds ciphertexts without the key."""
    def __init__(self, scheme: RLWEAdditive, edges):
        self.s = scheme; self.edges = np.asarray(edges); self.nb = len(edges) - 1
        assert self.nb <= scheme.p.n

    def encode(self, values):
        h, _ = np.histogram(values, bins=self.edges)
        v = np.zeros(self.s.p.n, np.int64); v[: self.nb] = np.minimum(h, self.s.p.t - 1); return v

    def report(self, values): return self.s.encrypt(self.encode(values))

    def aggregate(self, cts):
        acc = cts[0]
        for c in cts[1:]: acc = self.s.add(acc, c)
        return acc

    def open(self, ct): return self.s.decrypt(ct)[: self.nb]
