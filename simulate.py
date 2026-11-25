"""Federated training simulation on the synthetic generator (Sections 6.6, 6.16)."""
import numpy as np
from .robust import aggregate
from .dp import GaussianRDPAccountant, calibrate_sigma

def _sig(z): return 1 / (1 + np.exp(-np.clip(z, -30, 30)))

class LogisticModel:
    def __init__(self, d): self.w = np.zeros(d + 1)
    def predict_proba(self, X): return _sig(X @ self.w[:-1] + self.w[-1])
    def grad(self, X, y, l2=1e-3):
        p = self.predict_proba(X) - y; g = np.append(X.T @ p, p.sum()) / len(X); g[:-1] += l2 * self.w[:-1]; return g
    def f1(self, X, y):
        yp = self.predict_proba(X) > 0.5; tp = (yp & (y == 1)).sum(); fp = (yp & (y == 0)).sum(); fn = (~yp & (y == 1)).sum()
        return float(2 * tp / max(2 * tp + fp + fn, 1))
    def acc(self, X, y): return float(((self.predict_proba(X) > 0.5) == (y == 1)).mean())
    def fpr(self, X, y):
        yp = self.predict_proba(X) > 0.5; return float((yp & (y == 0)).sum() / max((y == 0).sum(), 1))

class MLPModel:
    """One-hidden-layer detector (ReLU) with a flat parameter vector so that FL can average it."""
    def __init__(self, d, hidden=16, seed=0):
        r = np.random.default_rng(seed); self.d, self.h = d, hidden
        W1 = r.standard_normal((d, hidden)) * np.sqrt(2 / d); W2 = r.standard_normal(hidden) * np.sqrt(1 / hidden)
        self.w = np.concatenate([W1.ravel(), np.zeros(hidden), W2, [0.0]])
    def _unpack(self):
        d, h = self.d, self.h; i = d * h
        return self.w[:i].reshape(d, h), self.w[i:i + h], self.w[i + h:i + 2 * h], self.w[-1]
    def _fwd(self, X):
        W1, b1, W2, b2 = self._unpack(); a = X @ W1 + b1; H = np.maximum(a, 0); return a, H, _sig(H @ W2 + b2)
    def predict_proba(self, X): return self._fwd(X)[2]
    def grad(self, X, y, l2=1e-4):
        W1, b1, W2, b2 = self._unpack(); a, H, p = self._fwd(X); e = (p - y) / len(X)
        gW2 = H.T @ e; gb2 = e.sum(); dH = np.outer(e, W2) * (a > 0)
        g = np.concatenate([(X.T @ dH).ravel() + l2 * W1.ravel(), dH.sum(0), gW2, [gb2]]); return g
    def input_grad(self, X, y):
        W1, b1, W2, b2 = self._unpack(); a, H, p = self._fwd(X); return np.outer(p - y, np.ones(self.h) * 0 + W2) * (a > 0) @ W1.T
    f1 = LogisticModel.f1; acc = LogisticModel.acc; fpr = LogisticModel.fpr

ATTACKS = ("none", "gradient_flip", "label_flip", "random_noise", "free_rider", "backdoor_scale")

class FLSimulation:
    def __init__(self, Xs, ys, mu, sd, n_byz=0, attack="none", method="mad_geomed", rounds=100, lr=0.5,
                 clip=2.0, dp_eps=None, delta=1e-5, local_steps=5, seed=0):
        self.Xs = [(X - mu) / sd for X in Xs]; self.ys = ys; self.K = len(Xs); self.byz = set(range(n_byz)); self.attack = attack
        self.method = method; self.rounds = rounds; self.lr = lr; self.clip = clip; self.ls = local_steps
        self.rng = np.random.default_rng(seed); self.d = Xs[0].shape[1]; self.model = MLPModel(self.d, seed=seed)
        self.sigma = calibrate_sigma(dp_eps, rounds, delta) if dp_eps else 0.0
        self.acct = GaussianRDPAccountant(self.sigma, delta) if dp_eps else None; self.log = []

    def _local(self, k, w):
        m = MLPModel(self.d); m.w = w.copy(); X, y = self.Xs[k], self.ys[k]
        if k in self.byz and self.attack == "label_flip": y = 1 - y
        for _ in range(self.ls):
            idx = self.rng.integers(0, len(X), min(64, len(X))); m.w -= self.lr * m.grad(X[idx], y[idx])
        u = m.w - w
        if k in self.byz:
            if self.attack == "gradient_flip": u = -5 * u
            elif self.attack == "random_noise": u = self.rng.standard_normal(u.shape) * 3
            elif self.attack == "free_rider": u = np.zeros_like(u)
            elif self.attack == "backdoor_scale": u = 10 * u
        return u

    def run(self, Xval, yval, checkpoints=(10, 25, 50, 100)):
        Xv = (Xval - self._mu_hint) / self._sd_hint if hasattr(self, "_mu_hint") else Xval
        for r in range(1, self.rounds + 1):
            U = np.stack([self._local(k, self.model.w) for k in range(self.K)])
            agg, keep = aggregate(U, self.method, clip=self.clip)
            if self.sigma > 0:
                agg = agg + self.rng.standard_normal(agg.shape) * self.sigma * self.clip / max(keep.sum(), 1); self.acct.step()
            self.model.w += agg
            if r in checkpoints: self.log.append((r, self.model.f1(Xv, yval)))
        return self

    def set_validation_norm(self, mu, sd): self._mu_hint, self._sd_hint = mu, sd
    def epsilon(self): return self.acct.epsilon() if self.acct else float("inf")
