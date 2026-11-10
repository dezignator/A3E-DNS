"""Composite Detection Score (CDS) — thesis Eq. 131, §6.9.1.

The CDS combines:

    * the area under the precision–recall curve (AUPRC),
    * the weighted F1 score,
    * a Jensen–Shannon divergence penalty against the benign distribution,

as the harmonic mean of the first two, minus a weighted divergence penalty:

    CDS = (2 · AUPRC · F1_weighted) / (AUPRC + F1_weighted)
          − λ · JSD(P_benign ‖ P_detected)                (Eq. 131)

The harmonic mean is the standard "F-score-like" aggregator between AUPRC
and weighted F1; the JSD penalty is added, not subtracted from inside the
harmonic mean, matching the thesis exactly. ``λ`` is set by cross-validation
on the validation split; the value actually used is recorded in
``docs/REPRODUCIBILITY.md``.

The CDS is stated in the thesis as the evaluation metric used in
Chapter 6. It is **not** proposed as a new metric; its properties follow
from those of its components.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

import numpy as np

from src.utils.metrics import (
    auprc,
    f1_weighted,
    jensen_shannon_divergence,
)

__all__ = [
    "DEFAULT_LAMBDA",
    "CompositeDetectionScore",
    "compute_cds",
    "compute_cds_from_confusion",
]

#: Default λ. The thesis reports the value chosen by cross-validation on
#: the validation split (§6.9.1); this constant is only a fallback and must
#: be overridden by the caller with the value recorded in the manifest.
DEFAULT_LAMBDA: float = 0.1


# --------------------------------------------------------------- result type
@dataclass(frozen=True)
class CompositeDetectionScore:
    """Container for the CDS and each of its constituent parts.

    Attributes
    ----------
    cds : float
        The Composite Detection Score itself (Eq. 131).
    auprc : float
        Area under the precision–recall curve.
    f1_weighted : float
        Weighted F1 score.
    jsd : float
        Jensen–Shannon divergence between the benign reference
        distribution and the detected-traffic distribution.
    harmonic_mean : float
        ``2·AUPRC·F1 / (AUPRC + F1)`` — the first term of Eq. 131.
    penalty : float
        ``λ · JSD`` — the subtracted term of Eq. 131.
    lambda_ : float
        The λ that was used.
    """

    cds: float
    auprc: float
    f1_weighted: float
    jsd: float
    harmonic_mean: float
    penalty: float
    lambda_: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------- core
def _harmonic_mean(a: float, b: float) -> float:
    """Harmonic mean of two non-negative numbers.

    Returns 0.0 when either argument is exactly 0 (matching the convention
    that the harmonic mean of 0 and x is 0).
    """
    if a <= 0.0 or b <= 0.0:
        return 0.0
    return (2.0 * a * b) / (a + b)


def compute_cds(
    y_true: np.ndarray,
    y_score: np.ndarray,
    p_benign: np.ndarray,
    p_detected: np.ndarray,
    *,
    lambda_: float = DEFAULT_LAMBDA,
    labels: list[int] | None = None,
    pos_label: int = 1,
) -> CompositeDetectionScore:
    """Compute the Composite Detection Score of Eq. 131.

    Parameters
    ----------
    y_true : array
        Ground-truth class labels.
    y_score : array
        Continuous scores (higher = more likely ``pos_label``).
    p_benign : array
        Empirical distribution of the benign reference (e.g. histogram of
        a detection statistic). Non-negative; will be normalised.
    p_detected : array
        Empirical distribution of the detected-traffic stream (same
        support as ``p_benign``). Non-negative; will be normalised.
    lambda_ : float
        Trade-off weight on the JSD penalty. Must be ≥ 0.
    labels : list of int, optional
        Class labels for the weighted F1. If ``None``, inferred.
    pos_label : int
        Positive class for the AUPRC.

    Returns
    -------
    CompositeDetectionScore
        A frozen dataclass holding the CDS and each component.

    Notes
    -----
    - AUPRC and weighted F1 are each bounded in [0, 1] in the usual
      detection setting; the harmonic mean is therefore also in [0, 1].
    - JSD with base 2 is bounded in [0, 1]; the penalty term is
      ``λ · JSD``.
    - The thesis does **not** clamp the CDS; it is reported as computed.
    """
    if lambda_ < 0.0:
        raise ValueError(f"lambda_ must be ≥ 0, got {lambda_}")

    y_true = np.asarray(y_true).ravel()
    y_score = np.asarray(y_score).ravel()
    if y_true.shape != y_score.shape:
        raise ValueError(f"shape mismatch: {y_true.shape} vs {y_score.shape}")

    a = auprc(y_true, y_score, pos_label=pos_label)
    f1 = f1_weighted(y_true, (y_score >= 0.5).astype(y_true.dtype) if y_score.dtype.kind != "i" else y_score, labels=labels)

    # `f1_weighted` above uses a 0.5 threshold on continuous scores; when the
    # caller passes already-hard labels (integer dtype), use them directly.
    if y_score.dtype.kind in {"i", "u", "b"}:
        f1 = f1_weighted(y_true, y_score.astype(np.int64), labels=labels)

    h = _harmonic_mean(a, f1)
    jsd = jensen_shannon_divergence(p_benign, p_detected, base=2.0)
    penalty = lambda_ * jsd
    cds = h - penalty

    return CompositeDetectionScore(
        cds=float(cds),
        auprc=float(a),
        f1_weighted=float(f1),
        jsd=float(jsd),
        harmonic_mean=float(h),
        penalty=float(penalty),
        lambda_=float(lambda_),
    )


def compute_cds_from_confusion(
    tp: float,
    fp: float,
    tn: float,
    fn: float,
    p_benign: np.ndarray,
    p_detected: np.ndarray,
    *,
    lambda_: float = DEFAULT_LAMBDA,
) -> CompositeDetectionScore:
    """CDS computed from a confusion matrix plus the two distributions.

    Useful when the classification decision has already been reduced to
    a confusion matrix (e.g. for a table). AUPRC is not recoverable from a
    single confusion matrix, so this function reports ``auprc = nan`` and
    computes the harmonic mean from the weighted F1 alone: it is intended
    as a **fallback for reporting**, not as a replacement for the full
    :func:`compute_cds`. Use :func:`compute_cds` whenever the raw scores
    are available.
    """
    tp, fp, tn, fn = float(tp), float(fp), float(tn), float(fn)
    total = tp + fp + tn + fn
    if total <= 0:
        raise ValueError("confusion matrix sums to zero")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    jsd = jensen_shannon_divergence(p_benign, p_detected, base=2.0)
    penalty = lambda_ * jsd
    cds = f1 - penalty   # AUPRC unrecoverable; document the substitution

    return CompositeDetectionScore(
        cds=float(cds),
        auprc=float("nan"),
        f1_weighted=float(f1),
        jsd=float(jsd),
        harmonic_mean=float(f1),
        penalty=float(penalty),
        lambda_=float(lambda_),
    )
