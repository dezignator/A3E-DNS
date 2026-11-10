"""Evaluation metrics used throughout the A3E-DNS artifact.

These are the primitive metrics from which the Composite Detection Score
(Eq. 131, see ``composite_detection_score``) is composed. The thesis
reports each metric with a 95% confidence interval over repeated runs
(§6.16.2); the CI is computed by ``bootstrap_ci`` on a per-run scalar.

The definitions follow §6.16 of the thesis:

    accuracy       = (TP + TN) / (TP + TN + FP + FN)
    fpr            = FP / (FP + TN)
    p99_latency    = 99th percentile of per-decision latencies
    auprc          = area under the precision–recall curve
    f1_weighted    = Σ_c (n_c / N) · F1_c
    cohens_d       = (mean_a − mean_b) / pooled_std
    jsd            = Jensen–Shannon divergence

All functions accept NumPy arrays, Python lists, or Pandas Series; the
last axis is treated as the sample axis unless stated otherwise.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np

__all__ = [
    "accuracy",
    "false_positive_rate",
    "precision_recall_f1",
    "f1_weighted",
    "auprc",
    "p99_latency",
    "mean_latency",
    "throughput_from_latencies",
    "cohens_d",
    "jensen_shannon_divergence",
    "bootstrap_ci",
]

_EPS = 1e-12


# ---------------------------------------------------------------- accuracy
def accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Overall accuracy ``(TP + TN) / (TP + TN + FP + FN)``."""
    y_true = np.asarray(y_true).ravel()
    y_pred = np.asarray(y_pred).ravel()
    if y_true.shape != y_pred.shape:
        raise ValueError(f"shape mismatch: {y_true.shape} vs {y_pred.shape}")
    if y_true.size == 0:
        raise ValueError("empty input")
    return float(np.mean(y_true == y_pred))


# ---------------------------------------------------------------- FPR
def false_positive_rate(y_true: np.ndarray, y_pred: np.ndarray, pos_label: int = 1) -> float:
    """False-positive rate ``FP / (FP + TN)`` for the given positive class."""
    y_true = np.asarray(y_true).ravel()
    y_pred = np.asarray(y_pred).ravel()
    if y_true.shape != y_pred.shape:
        raise ValueError(f"shape mismatch: {y_true.shape} vs {y_pred.shape}")
    neg = y_true != pos_label
    if not np.any(neg):
        return 0.0
    return float(np.sum((y_pred == pos_label) & neg) / np.sum(neg))


# ---------------------------------------------------------------- precision / recall / F1
def precision_recall_f1(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    pos_label: int = 1,
) -> tuple[float, float, float]:
    """Return ``(precision, recall, F1)`` for the given positive class."""
    y_true = np.asarray(y_true).ravel()
    y_pred = np.asarray(y_pred).ravel()
    tp = float(np.sum((y_true == pos_label) & (y_pred == pos_label)))
    fp = float(np.sum((y_true != pos_label) & (y_pred == pos_label)))
    fn = float(np.sum((y_true == pos_label) & (y_pred != pos_label)))
    precision = tp / (tp + fp + _EPS)
    recall    = tp / (tp + fn + _EPS)
    f1        = 2.0 * precision * recall / (precision + recall + _EPS)
    return precision, recall, f1


def f1_weighted(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: Sequence[int] | None = None,
) -> float:
    """Weighted F1 by class frequency.

    With ``labels=None`` the labels are inferred as ``sorted(unique(y_true) ∪ unique(y_pred))``.
    """
    y_true = np.asarray(y_true).ravel()
    y_pred = np.asarray(y_pred).ravel()
    if y_true.shape != y_pred.shape:
        raise ValueError(f"shape mismatch: {y_true.shape} vs {y_pred.shape}")
    if labels is None:
        labels = np.unique(np.concatenate([y_true, y_pred]))
    labels = np.asarray(labels)

    n = y_true.size
    if n == 0:
        raise ValueError("empty input")

    weighted = 0.0
    for label in labels:
        support = int(np.sum(y_true == label))
        if support == 0:
            continue
        p, r, f1 = precision_recall_f1(y_true, y_pred, pos_label=label)
        weighted += (support / n) * f1
    return float(weighted)


# ---------------------------------------------------------------- AUPRC
def auprc(
    y_true: np.ndarray,
    y_score: np.ndarray,
    pos_label: int = 1,
) -> float:
    """Area under the precision–recall curve (step-wise integration).

    Implemented without scikit-learn so the metric is available even when
    the dev extras are not installed. Matches ``sklearn.metrics.average_precision_score``
    to within float64 round-off.
    """
    y_true = np.asarray(y_true).ravel()
    y_score = np.asarray(y_score).ravel()
    if y_true.shape != y_score.shape:
        raise ValueError(f"shape mismatch: {y_true.shape} vs {y_score.shape}")

    y_bin = (y_true == pos_label).astype(np.int64)
    if y_bin.sum() == 0:
        return 0.0

    # Sort by descending score; stable sort preserves order among ties.
    order = np.argsort(-y_score, kind="stable")
    y_sorted = y_bin[order]

    tp = np.cumsum(y_sorted)
    fp = np.cumsum(1 - y_sorted)
    precision = tp / np.maximum(tp + fp, _EPS)
    recall    = tp / max(int(y_bin.sum()), 1)

    # Prepend (recall=0, precision=1) so the step-wise integral is well-defined.
    precision = np.concatenate(([1.0], precision))
    recall    = np.concatenate(([0.0], recall))

    # Step-wise integral: AP = Σ (R_k − R_{k−1}) · P_k
    dr = np.diff(recall)
    ap = float(np.sum(dr * precision[1:]))
    return ap


# ---------------------------------------------------------------- latency
def p99_latency(latencies: np.ndarray) -> float:
    """99th percentile of the per-decision latencies (in the input unit)."""
    latencies = np.asarray(latencies).ravel()
    if latencies.size == 0:
        raise ValueError("empty input")
    return float(np.percentile(latencies, 99))


def mean_latency(latencies: np.ndarray) -> float:
    """Arithmetic mean of the per-decision latencies."""
    latencies = np.asarray(latencies).ravel()
    if latencies.size == 0:
        raise ValueError("empty input")
    return float(np.mean(latencies))


def throughput_from_latencies(
    latencies_ms: np.ndarray,
    *,
    parallel_workers: int = 1,
) -> float:
    """Estimate throughput (QPS) from per-decision latencies in milliseconds.

    ``QPS = 1000 / mean_latency_ms · parallel_workers``. The parallel
    workers factor is the number of concurrent processing units (matching
    Eq. 31 in the thesis, ``C_parallel``).
    """
    latencies_ms = np.asarray(latencies_ms).ravel()
    if latencies_ms.size == 0:
        raise ValueError("empty input")
    if parallel_workers < 1:
        raise ValueError("parallel_workers must be ≥ 1")
    mean_ms = float(np.mean(latencies_ms))
    if mean_ms <= 0:
        return float("inf")
    return (1000.0 / mean_ms) * parallel_workers


# ---------------------------------------------------------------- effect size
def cohens_d(a: np.ndarray, b: np.ndarray) -> float:
    """Cohen's *d* effect size (pooled standard deviation).

    Matches the reported effect size in §6.16.2 (``d = 1.87`` for the
    FPR comparison against DNSGuard).
    """
    a = np.asarray(a).ravel()
    b = np.asarray(b).ravel()
    na, nb = a.size, b.size
    if na < 2 or nb < 2:
        raise ValueError("cohens_d: each sample must have at least 2 elements")
    pooled_var = (((na - 1) * np.var(a, ddof=1)) + ((nb - 1) * np.var(b, ddof=1))) / (na + nb - 2)
    pooled_std = float(np.sqrt(pooled_var))
    if pooled_std <= 0:
        return 0.0
    return float((np.mean(a) - np.mean(b)) / pooled_std)


# ---------------------------------------------------------------- divergence
def jensen_shannon_divergence(
    p: np.ndarray,
    q: np.ndarray,
    *,
    base: float = 2.0,
) -> float:
    """Jensen–Shannon divergence ``JSD(p ‖ q)`` in [0, 1] (with base 2).

    ``p`` and ``q`` must be non-negative and sum to a positive value; they
    are normalised before the divergence is computed.
    """
    p = np.asarray(p, dtype=np.float64).ravel()
    q = np.asarray(q, dtype=np.float64).ravel()
    if p.shape != q.shape:
        raise ValueError(f"shape mismatch: {p.shape} vs {q.shape}")
    if np.any(p < 0) or np.any(q < 0):
        raise ValueError("jsd: inputs must be non-negative")
    sp, sq = p.sum(), q.sum()
    if sp <= 0 or sq <= 0:
        raise ValueError("jsd: inputs must have positive mass")
    p = p / sp
    q = q / sq
    m = 0.5 * (p + q)

    def _kl(a: np.ndarray, b: np.ndarray) -> float:
        mask = a > 0
        if not np.any(mask):
            return 0.0
        return float(np.sum(a[mask] * np.log(a[mask] / b[mask])))

    if base == 2.0:
        log_base = np.log(2.0)
    else:
        log_base = np.log(base)

    return (_kl(p, m) + _kl(q, m)) / (2.0 * log_base)


# ---------------------------------------------------------------- CI
def bootstrap_ci(
    values: np.ndarray,
    *,
    n_resamples: int = 1000,
    confidence: float = 0.95,
    statistic: str = "mean",
    rng: np.random.Generator | None = None,
) -> tuple[float, float]:
    """Percentile bootstrap confidence interval.

    Parameters
    ----------
    values : array
        Per-run scalar measurements (e.g. one accuracy per repeat).
    n_resamples : int
        Number of bootstrap resamples.
    confidence : float
        Confidence level in ``(0, 1)``. Default ``0.95`` matches §6.16.2.
    statistic : {"mean", "median"}
        Which point statistic to bootstrap.
    rng : numpy.random.Generator, optional
        Source of randomness. If ``None``, a fresh generator seeded from
        the global NumPy RNG is used (deterministic given the caller's
        seed).

    Returns
    -------
    (lo, hi) : tuple of floats
    """
    values = np.asarray(values, dtype=np.float64).ravel()
    if values.size < 2:
        raise ValueError("bootstrap_ci: need at least 2 samples")
    if not (0.0 < confidence < 1.0):
        raise ValueError("bootstrap_ci: confidence must be in (0, 1)")

    rng = rng if rng is not None else np.random.default_rng()
    n = values.size
    idx = rng.integers(0, n, size=(n_resamples, n))
    samples = values[idx]

    if statistic == "mean":
        stats = samples.mean(axis=1)
    elif statistic == "median":
        stats = np.median(samples, axis=1)
    else:
        raise ValueError(f"bootstrap_ci: unknown statistic {statistic!r}")

    alpha = (1.0 - confidence) / 2.0
    lo = float(np.percentile(stats, 100.0 * alpha))
    hi = float(np.percentile(stats, 100.0 * (1.0 - alpha)))
    return lo, hi
