"""Spatio-temporal attention with exponential temporal decay (Section 6.6.1).

Forward pass only. Attention logits are q.k / sqrt(d) minus a temporal
penalty gamma*|i-j|, so older packets weigh less. The module is used to
check shape and decay properties; training of the 8-layer, 12-head
detector in Table 27 is in notebooks_v2 / torch_detector_v2.py.
"""
import numpy as np

def temporal_decay(T, gamma=0.05):
    i = np.arange(T)[:, None]; j = np.arange(T)[None, :]
    return np.exp(-gamma * np.abs(i - j))

def _softmax(x):
    x = x - x.max(-1, keepdims=True); e = np.exp(x); return e / e.sum(-1, keepdims=True)

class SpatioTemporalAttention:
    def __init__(self, d_model=48, heads=12, gamma=0.05, seed=0, window=512):
        assert d_model % heads == 0
        r = np.random.default_rng(seed); self.h = heads; self.dk = d_model // heads; self.g = gamma; self.window = window
        self.Wq, self.Wk, self.Wv, self.Wo = (r.standard_normal((d_model, d_model)) / np.sqrt(d_model) for _ in range(4))

    def __call__(self, X):
        T = X.shape[0]; assert T <= self.window
        Q, K, V = X @ self.Wq, X @ self.Wk, X @ self.Wv
        out = np.zeros_like(X); self.last_attn = []
        for h in range(self.h):
            s = slice(h * self.dk, (h + 1) * self.dk)
            logits = Q[:, s] @ K[:, s].T / np.sqrt(self.dk) + np.log(temporal_decay(T, self.g))
            A = _softmax(logits); self.last_attn.append(A); out[:, s] = A @ V[:, s]
        return out @ self.Wo
