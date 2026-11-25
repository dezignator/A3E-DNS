"""Byzantine-robust aggregation (Sections 6.6.4, 6.9.3)."""
import numpy as np

def clip_updates(U, c):
    n = np.linalg.norm(U, axis=1, keepdims=True); return U * np.minimum(1.0, c / np.maximum(n, 1e-12))

def geometric_median(U, iters=100, tol=1e-7, w=None):
    w = np.ones(len(U)) if w is None else np.asarray(w, float)
    z = (U * w[:, None]).sum(0) / w.sum()
    for _ in range(iters):
        d = np.maximum(np.linalg.norm(U - z, axis=1), 1e-12); a = w / d
        z2 = (U * a[:, None]).sum(0) / a.sum()
        if np.linalg.norm(z2 - z) < tol: return z2
        z = z2
    return z

def coordinate_median(U): return np.median(U, axis=0)

def trimmed_mean(U, beta=0.2):
    k = int(beta * len(U)); S = np.sort(U, axis=0); return S[k: len(U) - k].mean(0)

def mad_filter(U, k=3.0):
    """Drop clients whose distance to the coordinate median exceeds median + k * 1.4826 * MAD."""
    d = np.linalg.norm(U - np.median(U, 0), axis=1); m = np.median(d); mad = 1.4826 * np.median(np.abs(d - m)) + 1e-12
    return d <= m + k * mad

def aggregate(U, method="mad_geomed", clip=None, beta=0.2, w=None):
    if clip is not None: U = clip_updates(U, clip)
    if method == "mean": return U.mean(0), np.ones(len(U), bool)
    if method == "median": return coordinate_median(U), np.ones(len(U), bool)
    if method == "trimmed": return trimmed_mean(U, beta), np.ones(len(U), bool)
    if method == "geomed": return geometric_median(U, w=w), np.ones(len(U), bool)
    if method == "mad_geomed":
        keep = mad_filter(U); return geometric_median(U[keep], w=None if w is None else np.asarray(w)[keep]), keep
    raise ValueError(method)
