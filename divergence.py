import numpy as np
def kl(p, q, eps=1e-12):
    p = np.asarray(p, float) + eps; q = np.asarray(q, float) + eps; p /= p.sum(); q /= q.sum(); return float(np.sum(p * np.log(p / q)))
def renyi(p, q, alpha=2.0, eps=1e-12):
    p = np.asarray(p, float) + eps; q = np.asarray(q, float) + eps; p /= p.sum(); q /= q.sum()
    return float(np.log(np.sum(p**alpha * q**(1 - alpha))) / (alpha - 1))
