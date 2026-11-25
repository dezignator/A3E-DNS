"""Lightweight neural controller (Section 6.4.5): 2 hidden layers x 64 units."""
import numpy as np

def window_features(sizes, iats, qname_entropy=0.0, proto_onehot=(1, 0, 0), bins=8):
    """Statistics over the last 1,000 packets (16 dimensions)."""
    sizes = np.asarray(sizes[-1000:], float); iats = np.asarray(iats[-1000:], float)
    def mom(x):
        m, s = x.mean(), x.std() + 1e-9
        return [m, s, float(((x - m)**3).mean() / s**3), float(((x - m)**4).mean() / s**4)]
    h, _ = np.histogram(iats, bins=bins, range=(0, max(1.0, iats.max()))); p = h / max(h.sum(), 1)
    ent = float(-(p[p > 0] * np.log2(p[p > 0])).sum())
    return np.array(mom(sizes) + mom(iats) + [ent, qname_entropy] + list(proto_onehot) + [0.0, 0.0], float)

class NeuralController:
    def __init__(self, in_dim=16, hidden=64, out_dim=24, seed=0):
        r = np.random.default_rng(seed)
        self.W1 = r.standard_normal((in_dim, hidden)) * np.sqrt(2 / in_dim); self.b1 = np.zeros(hidden)
        self.W2 = r.standard_normal((hidden, hidden)) * np.sqrt(2 / hidden); self.b2 = np.zeros(hidden)
        self.W3 = r.standard_normal((hidden, out_dim)) * 0.05; self.b3 = np.zeros(out_dim)
        self.mu = np.zeros(in_dim); self.sd = np.ones(in_dim)

    def fit_normaliser(self, X): self.mu, self.sd = X.mean(0), X.std(0) + 1e-9

    def __call__(self, x):
        z = (x - self.mu) / self.sd
        h = np.maximum(z @ self.W1 + self.b1, 0); h = np.maximum(h @ self.W2 + self.b2, 0)
        return np.tanh(h @ self.W3 + self.b3)

    def n_params(self): return sum(a.size for a in (self.W1, self.b1, self.W2, self.b2, self.W3, self.b3))

    def quantize_int8(self):
        for name in ("W1", "W2", "W3"):
            W = getattr(self, name); s = np.abs(W).max() / 127 + 1e-12
            setattr(self, name, np.round(W / s) * s)
        return self

    def prune(self, frac=0.3):
        for name in ("W1", "W2"):
            W = getattr(self, name); thr = np.quantile(np.abs(W), frac); W[np.abs(W) < thr] = 0
        return self
