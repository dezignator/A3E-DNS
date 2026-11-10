"""Byzantine-robust aggregation via weighted geometric median — §6.6.4.

Implements Eq. 127 and Eq. 128 of the thesis:

    θ^{t+1} = Median({θ_i^t}_{i=1}^N) + (1/t) Σ_{i ∈ H} Clip_C(∇ℓ_i(θ^t))
    Clip_C(v) = v · min(1, C / ‖v‖_2)

The geometric median is the point that minimizes the sum of Euclidean
distances to the client updates. It has bounded sensitivity to a
fraction of Byzantine clients: no single client (or small coalition) can
move the median arbitrarily far.

The implementation uses the Weiszfeld algorithm with the standard
"modified" step for exact-iteration safety when the iterand lands on one
of the points.

References (published constructions; not new):
    * Weiszfeld (1937), the original geometric median iteration.
    * Vardi & Zhang (2000), the modified Weiszfeld with the boundary case.
    * Chen, Kar, and Moura (2017), Byzantine-robust aggregation via
      geometric median in distributed learning.
"""

from __future__ import annotations

import numpy as np

__all__ = [
    "weighted_geometric_median",
    "clip_by_norm",
    "mad_threshold",
]


# --------------------------------------------------------------- clip
def clip_by_norm(v: np.ndarray, C: float) -> np.ndarray:
    """L2 clipping ``Clip_C(v) = v · min(1, C / ‖v‖_2)``.

    Parameters
    ----------
    v : np.ndarray
        Vector to clip.
    C : float
        Clipping bound. Must be > 0.
    """
    if C <= 0.0:
        raise ValueError(f"C must be > 0, got {C}")
    v = np.asarray(v, dtype=np.float64)
    norm = float(np.linalg.norm(v))
    if norm <= C:
        return v
    return v * (C / norm)


# --------------------------------------------------------------- MAD
def mad_threshold(values: np.ndarray, sigma: float = 2.5) -> float:
    """Return ``median + sigma × MAD`` for the given values.

    ``MAD`` is the median absolute deviation from the median, scaled by
    ``1.4826`` (the standard normal consistency constant) so that
    ``sigma = 2.5`` corresponds to the thesis's ``MAD > 2.5σ`` rule.
    """
    if sigma <= 0.0:
        raise ValueError(f"sigma must be > 0, got {sigma}")
    values = np.asarray(values, dtype=np.float64).ravel()
    if values.size == 0:
        raise ValueError("empty input")
    med = float(np.median(values))
    mad = float(np.median(np.abs(values - med))) * 1.4826
    return med + sigma * mad


# --------------------------------------------------------------- WGM
def weighted_geometric_median(
    points: np.ndarray,
    weights: np.ndarray | None = None,
    *,
    max_iter: int = 500,
    tol: float = 1e-8,
) -> np.ndarray:
    """Weighted geometric median of a set of points.

    Parameters
    ----------
    points : np.ndarray, shape ``(n, d)``
        The client updates, one row per client.
    weights : np.ndarray, shape ``(n,)``, optional
        Client weights. Must be non-negative and have positive sum. If
        ``None``, uniform weights are used.
    max_iter : int
        Maximum number of Weiszfeld iterations.
    tol : float
        Convergence tolerance on the iterate change.

    Returns
    -------
    np.ndarray, shape ``(d,)``
        The weighted geometric median.

    Notes
    -----
    * The modified Weiszfeld step handles the case where the iterate
      lands exactly on one of the points.
    * The algorithm is deterministic given the input; no RNG is used.
    """
    points = np.asarray(points, dtype=np.float64)
    if points.ndim != 2:
        raise ValueError(f"points must be 2-D, got shape {points.shape}")
    n, d = points.shape
    if n == 0:
        raise ValueError("points must be non-empty")
    if d == 0:
        raise ValueError("points must have at least one dimension")

    if weights is None:
        w = np.ones(n, dtype=np.float64)
    else:
        w = np.asarray(weights, dtype=np.float64).ravel()
        if w.shape != (n,):
            raise ValueError(f"weights must have shape ({n},), got {w.shape}")
        if np.any(w < 0):
            raise ValueError("weights must be non-negative")
    w_sum = float(w.sum())
    if w_sum <= 0.0:
        raise ValueError("weights must have positive sum")
    w = w / w_sum

    # Start at the weighted mean (a standard warm start).
    x = (w[:, None] * points).sum(axis=0)

    for _ in range(max_iter):
        diffs = points - x[None, :]
        dists = np.linalg.norm(diffs, axis=1)
        # Distance floor to avoid division by zero when the iterate
        # coincides with a point.
        eps = 1e-12
        nonzero = dists > eps
        if not nonzero.any():
            return x
        w_eff = w[nonzero] / np.maximum(dists[nonzero], eps)
        w_eff_sum = float(w_eff.sum())
        x_next = (w_eff[:, None] * points[nonzero]).sum(axis=0) / w_eff_sum
        if np.linalg.norm(x_next - x) < tol:
            return x_next
        x = x_next

    return x
