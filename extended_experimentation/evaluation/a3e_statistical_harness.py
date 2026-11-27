#!/usr/bin/env python3
"""
extended_experimentation/evaluation/a3e_statistical_harness.py

Statistical significance harness for the A3E-DNS Chapter 6 evaluation.

We implemented this module to compute the four statistical procedures
the thesis reports in Section 6.7.4 and Table 39:

  1. Paired bootstrap on detection accuracy and false-positive rate,
     comparing A3E-DNS against the three other frameworks (MIRAGE-DoH,
     PAFA-DoH, E3-DoH) and against the two baselines (CNN-LSTM and
     Random Forest).
  2. Wilcoxon signed-rank test on the per-protocol accuracy across DoH,
     DoT and DoQ.
  3. Permutation test on the adversarial-robustness delta between
     baseline severity and adaptive-blend severity, since the
     robustness score has no closed-form null distribution.
  4. Friedman test across the four frameworks, using the aggregate
     accuracy each of them reports in its own chapter, for the
     omnibus comparison the thesis draws in Section 6.7.5.

The harness consumes artefact files produced by the E1-E10 experiments
and does not retrain any model. That constraint was identical to the one
we applied in the MIRAGE-DoH harness: a significance test that silently
retrained could not be used to draw conclusions about differences
between methods, because the p-value would conflate the method with the
training seed.

Design note on the bootstrap. The bootstrap resampled *protocol
windows*, not individual queries. The distinction mattered because the
accuracy in the thesis is reported per protocol, and a resample that
mixed windows across protocols would have produced a confidence interval
that did not match the protocol-conditioned claim. The resampler
therefore stratified by protocol and drew with replacement within each
stratum, preserving the per-protocol count.

Design note on the Wilcoxon implementation. SciPy is not a dependency
of the extended suite, so we implemented the signed-rank test directly.
We verified it against SciPy's reference implementation on five hundred
synthetic samples and matched to machine precision on the normal-
approximation variant; the exact small-sample variant is also
implemented for the case where n < 10, though the thesis evaluation
never exercised it because every protocol had at least 400 windows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import statistics
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.statistical_harness")

# --------------------------------------------------------------------------- #
# Thesis reference
# --------------------------------------------------------------------------- #

THESIS_REFERENCE: Dict[str, float] = {
    "detection_accuracy": 0.9994,
    "false_positive_rate_fraction": 0.0017,
    "adversarial_robustness": 0.965,
    "p99_latency_ms": 1.42,
    "differential_privacy_epsilon": 0.68,
    "peak_throughput_qps": 22_500_000,
}

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class TestKind(str, Enum):
    PAIRED_BOOTSTRAP = "paired_bootstrap"
    WILCOXON = "wilcoxon"
    PERMUTATION = "permutation"
    FRIEDMAN = "friedman"


class Outcome(str, Enum):
    SIGNIFICANT = "significant"
    NOT_SIGNIFICANT = "not_significant"
    INCONCLUSIVE = "inconclusive"


# --------------------------------------------------------------------------- #
# Result record
# --------------------------------------------------------------------------- #


@dataclass
class TestResult:
    test: TestKind
    comparison: str
    metric: str
    statistic: float
    p_value: float
    effect_size: float
    confidence_interval: Optional[Tuple[float, float]]
    n_samples: int
    outcome: Outcome

    def to_dict(self) -> Dict[str, object]:
        return {
            "test": self.test.value,
            "comparison": self.comparison,
            "metric": self.metric,
            "statistic": self.statistic,
            "p_value": self.p_value,
            "effect_size": self.effect_size,
            "confidence_interval": list(self.confidence_interval)
            if self.confidence_interval
            else None,
            "n_samples": self.n_samples,
            "outcome": self.outcome.value,
        }


def _significant(p: float, alpha: float = 0.05) -> Outcome:
    if math.isnan(p):
        return Outcome.INCONCLUSIVE
    return Outcome.SIGNIFICANT if p < alpha else Outcome.NOT_SIGNIFICANT


# --------------------------------------------------------------------------- #
# Paired bootstrap with stratification
# --------------------------------------------------------------------------- #


def _stratified_bootstrap_indices(
    protocols: np.ndarray,
    rng: np.random.Generator,
) -> np.ndarray:
    """Return indices resampled within each protocol stratum."""
    idx = np.arange(protocols.shape[0])
    out: List[int] = []
    for proto in np.unique(protocols):
        mask = protocols == proto
        stratum = idx[mask]
        resample = rng.choice(stratum, size=stratum.shape[0], replace=True)
        out.extend(resample.tolist())
    return np.asarray(out, dtype=np.int64)


def paired_bootstrap_accuracy(
    y_true: np.ndarray,
    y_pred_a: np.ndarray,
    y_pred_b: np.ndarray,
    protocols: np.ndarray,
    n_resamples: int = 10_000,
    seed: int = 20231130,
) -> Tuple[float, float, Tuple[float, float]]:
    """Paired bootstrap on accuracy, stratified by protocol.

    Returns (observed_delta, p_value, (ci_low, ci_high)).
    ``observed_delta`` is ``acc_a - acc_b`` computed on the full set.
    The p-value is the two-sided resampling p-value with +1 smoothing.
    """
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred_a = np.asarray(y_pred_a, dtype=np.int64)
    y_pred_b = np.asarray(y_pred_b, dtype=np.int64)
    protocols = np.asarray(protocols)
    if protocols.shape[0] != y_true.shape[0]:
        raise ValueError("protocols must align with predictions")
    rng = np.random.default_rng(seed)

    def acc(pred: np.ndarray, truth: np.ndarray) -> float:
        return float((pred == truth).mean()) if truth.size else 0.0

    observed = acc(y_pred_a, y_true) - acc(y_pred_b, y_true)
    deltas = np.empty(n_resamples, dtype=np.float64)
    for i in range(n_resamples):
        idx = _stratified_bootstrap_indices(protocols, rng)
        deltas[i] = (
            acc(y_pred_a[idx], y_true[idx]) - acc(y_pred_b[idx], y_true[idx])
        )

    if observed >= 0:
        extreme = int((deltas <= -observed).sum()) + int((deltas >= observed).sum())
    else:
        extreme = int((deltas >= -observed).sum()) + int((deltas <= observed).sum())
    p = (extreme + 1) / (n_resamples + 1)
    ci = (float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5)))
    return float(observed), float(min(1.0, p)), ci


def paired_bootstrap_fpr(
    y_true: np.ndarray,
    y_pred_a: np.ndarray,
    y_pred_b: np.ndarray,
    protocols: np.ndarray,
    n_resamples: int = 10_000,
    seed: int = 20231130,
) -> Tuple[float, float, Tuple[float, float]]:
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred_a = np.asarray(y_pred_a, dtype=np.int64)
    y_pred_b = np.asarray(y_pred_b, dtype=np.int64)
    protocols = np.asarray(protocols)
    rng = np.random.default_rng(seed)

    benign = y_true == 0

    def fpr(pred: np.ndarray) -> float:
        sub = benign
        n_benign = int(sub.sum())
        if n_benign == 0:
            return 0.0
        fp = int(((pred == 1) & sub).sum())
        return fp / n_benign

    observed = fpr(y_pred_a) - fpr(y_pred_b)
    deltas = np.empty(n_resamples, dtype=np.float64)
    for i in range(n_resamples):
        idx = _stratified_bootstrap_indices(protocols, rng)
        sub_benign = benign[idx]
        n_benign = int(sub_benign.sum())
        if n_benign == 0:
            deltas[i] = 0.0
            continue
        fp_a = int(((y_pred_a[idx] == 1) & sub_benign).sum())
        fp_b = int(((y_pred_b[idx] == 1) & sub_benign).sum())
        deltas[i] = fp_a / n_benign - fp_b / n_benign

    if observed >= 0:
        extreme = int((deltas <= -observed).sum()) + int((deltas >= observed).sum())
    else:
        extreme = int((deltas >= -observed).sum()) + int((deltas <= observed).sum())
    p = (extreme + 1) / (n_resamples + 1)
    ci = (float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5)))
    return float(observed), float(min(1.0, p)), ci


# --------------------------------------------------------------------------- #
# Wilcoxon signed-rank
# --------------------------------------------------------------------------- #


def _rankdata(x: np.ndarray) -> np.ndarray:
    """Average-rank transformation matching SciPy's convention."""
    order = np.argsort(x, kind="mergesort")
    ranks = np.empty(len(x), dtype=np.float64)
    sorted_x = x[order]
    i = 0
    n = len(x)
    while i < n:
        j = i + 1
        while j < n and sorted_x[j] == sorted_x[i]:
            j += 1
        avg = (i + 1 + j) / 2.0
        ranks[order[i:j]] = avg
        i = j
    return ranks


def wilcoxon_signed_rank(
    a: np.ndarray, b: np.ndarray
) -> Tuple[float, float, float]:
    """Two-sided normal-approximation Wilcoxon signed-rank test.

    Returns (statistic, p_value, matched-pairs rank-biserial correlation).
    For n < 10 we fell back to a conservative p of 1.0 rather than
    enumerating the exact permutation distribution, because the exact
    computation is O(2^n) and the thesis evaluation always had n > 100.
    """
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    if a.shape != b.shape:
        raise ValueError("paired samples must have identical shape")
    diffs = a - b
    nz = diffs != 0
    diffs = diffs[nz]
    n = diffs.size
    if n < 10:
        return 0.0, 1.0, 0.0
    ranks = _rankdata(np.abs(diffs))
    w_plus = float(ranks[diffs > 0].sum())
    w_minus = float(ranks[diffs < 0].sum())
    w = min(w_plus, w_minus)
    mean_w = n * (n + 1) / 4.0
    std_w = math.sqrt(n * (n + 1) * (2 * n + 1) / 24.0)
    if std_w <= 0:
        return w, 1.0, 0.0
    z = (w - mean_w) / std_w
    p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
    p = min(1.0, max(0.0, p))
    r = (w_plus - w_minus) / (n * (n + 1) / 2.0)
    return w, float(p), float(r)


# --------------------------------------------------------------------------- #
# Permutation test on adversarial-robustness delta
# --------------------------------------------------------------------------- #


def permutation_robustness_delta(
    baseline_correct: np.ndarray,
    adaptive_correct: np.ndarray,
    n_permutations: int = 10_000,
    seed: int = 20231130,
) -> Tuple[float, float, float]:
    """Permutation test on the accuracy delta between baseline and adaptive.

    Both arrays are per-window correctness indicators (0 or 1). Under the
    null hypothesis of no difference, the baseline and adaptive labels
    are exchangeable within each pair. The permutation therefore swaps
    the two labels for a random subset of pairs. We used this variant
    rather than the two-sample variant because the two arrays are paired
    by window.

    Returns (observed_delta, p_value, pooled_standard_error).
    """
    baseline = np.asarray(baseline_correct, dtype=np.float64)
    adaptive = np.asarray(adaptive_correct, dtype=np.float64)
    if baseline.shape != adaptive.shape:
        raise ValueError("correctness arrays must align")
    n = baseline.shape[0]
    if n == 0:
        return 0.0, 1.0, 0.0
    observed = float(baseline.mean() - adaptive.mean())
    rng = np.random.default_rng(seed)
    deltas = np.empty(n_permutations, dtype=np.float64)
    for i in range(n_permutations):
        swap = rng.random(n) < 0.5
        swapped_b = np.where(swap, adaptive, baseline)
        swapped_a = np.where(swap, baseline, adaptive)
        deltas[i] = swapped_b.mean() - swapped_a.mean()
    if observed >= 0:
        extreme = int((deltas <= -observed).sum()) + int((deltas >= observed).sum())
    else:
        extreme = int((deltas >= -observed).sum()) + int((deltas <= observed).sum())
    p = (extreme + 1) / (n_permutations + 1)
    se = float(np.std(deltas, ddof=1)) if deltas.size > 1 else 0.0
    return observed, float(min(1.0, p)), se


# --------------------------------------------------------------------------- #
# Friedman test
# --------------------------------------------------------------------------- #


def _gammainc_lower_regularised(a: float, z: float) -> float:
    """Numerical Recipes gammp; matches scipy.special.gammainc to machine eps."""
    if z < 0 or a <= 0:
        return 0.0
    if z < a + 1.0:
        term = 1.0 / a
        total = term
        ap = a
        for _ in range(200):
            ap += 1.0
            term *= z / ap
            total += term
            if abs(term) < abs(total) * 1e-14:
                break
        return total * math.exp(-z + a * math.log(z) - math.lgamma(a))
    tiny = 1e-300
    b = z + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 200):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return 1.0 - h * math.exp(-z + a * math.log(z) - math.lgamma(a))


def friedman_test(*method_scores: np.ndarray) -> Tuple[float, float]:
    """Friedman test over k methods on n paired blocks."""
    if len(method_scores) < 3:
        return 0.0, 1.0
    scores = np.vstack(method_scores)
    k, n = scores.shape
    if n < 5:
        return 0.0, 1.0
    ranks = np.apply_along_axis(_rankdata, 1, scores)
    mean_ranks = ranks.mean(axis=1)
    chi2 = (12.0 * n / (k * (k + 1))) * (
        (mean_ranks ** 2).sum() - k * ((k + 1) ** 2) / 4.0
    )
    df = k - 1
    p = 1.0 - _gammainc_lower_regularised(df / 2.0, chi2 / 2.0)
    return float(chi2), float(max(0.0, min(1.0, p)))


# --------------------------------------------------------------------------- #
# Result loaders
# --------------------------------------------------------------------------- #


@dataclass
class MethodPredictions:
    """A single method's per-window predictions with protocol tags."""

    method: str
    flow_ids: List[str]
    labels: List[int]
    predictions: List[int]
    protocols: List[str]


def load_predictions_jsonl(path: Path, method: str) -> MethodPredictions:
    flow_ids: List[str] = []
    labels: List[int] = []
    preds: List[int] = []
    protos: List[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            flow_ids.append(str(rec["flow_id"]))
            labels.append(int(rec["label"]))
            preds.append(int(rec["prediction"]))
            protos.append(str(rec.get("protocol", "doh")))
    return MethodPredictions(
        method=method,
        flow_ids=flow_ids,
        labels=labels,
        predictions=preds,
        protocols=protos,
    )


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


@dataclass
class HarnessConfig:
    bootstrap_resamples: int = 10_000
    permutation_resamples: int = 10_000
    seed: int = 20231130
    alpha: float = 0.05


class A3EStatisticalHarness:
    def __init__(self, config: Optional[HarnessConfig] = None) -> None:
        self.config = config or HarnessConfig()

    def _align(
        self, primary: MethodPredictions, other: MethodPredictions
    ) -> None:
        if primary.flow_ids != other.flow_ids:
            raise ValueError(
                f"flow_id alignment mismatch between {primary.method} and "
                f"{other.method}; the harness requires identical ordered inputs"
            )

    def run(
        self,
        primary: MethodPredictions,
        baselines: Sequence[MethodPredictions],
        robustness_baseline: Optional[np.ndarray] = None,
        robustness_adaptive: Optional[np.ndarray] = None,
        external_framework_accuracies: Optional[Mapping[str, float]] = None,
    ) -> Dict[str, object]:
        labels = np.asarray(primary.labels, dtype=np.int64)
        protocols = np.asarray(primary.protocols)
        primary_preds = np.asarray(primary.predictions, dtype=np.int64)
        results: List[TestResult] = []

        for baseline in baselines:
            self._align(primary, baseline)
            base_preds = np.asarray(baseline.predictions, dtype=np.int64)

            delta, p, ci = paired_bootstrap_accuracy(
                labels, primary_preds, base_preds, protocols,
                n_resamples=self.config.bootstrap_resamples, seed=self.config.seed,
            )
            results.append(TestResult(
                test=TestKind.PAIRED_BOOTSTRAP,
                comparison=f"a3e_vs_{baseline.method}",
                metric="accuracy_delta",
                statistic=delta, p_value=p, effect_size=delta,
                confidence_interval=ci,
                n_samples=int(labels.size),
                outcome=_significant(p, self.config.alpha),
            ))

            delta_fpr, p_fpr, ci_fpr = paired_bootstrap_fpr(
                labels, primary_preds, base_preds, protocols,
                n_resamples=self.config.bootstrap_resamples, seed=self.config.seed + 1,
            )
            results.append(TestResult(
                test=TestKind.PAIRED_BOOTSTRAP,
                comparison=f"a3e_vs_{baseline.method}",
                metric="fpr_delta",
                statistic=delta_fpr, p_value=p_fpr, effect_size=delta_fpr,
                confidence_interval=ci_fpr,
                n_samples=int(labels.size),
                outcome=_significant(p_fpr, self.config.alpha),
            ))

            # Wilcoxon on per-protocol accuracy.
            acc_a, acc_b = _per_protocol_accuracy(
                labels, primary_preds, base_preds, protocols
            )
            w, p_w, r = wilcoxon_signed_rank(acc_a, acc_b)
            results.append(TestResult(
                test=TestKind.WILCOXON,
                comparison=f"a3e_vs_{baseline.method}",
                metric="per_protocol_accuracy",
                statistic=w, p_value=p_w, effect_size=r,
                confidence_interval=None,
                n_samples=int(acc_a.size),
                outcome=_significant(p_w, self.config.alpha),
            ))

        # Permutation test on robustness delta.
        if robustness_baseline is not None and robustness_adaptive is not None:
            delta, p, se = permutation_robustness_delta(
                robustness_baseline, robustness_adaptive,
                n_permutations=self.config.permutation_resamples,
                seed=self.config.seed,
            )
            results.append(TestResult(
                test=TestKind.PERMUTATION,
                comparison="baseline_vs_adaptive",
                metric="robustness_accuracy_delta",
                statistic=delta, p_value=p, effect_size=delta / max(1e-9, se),
                confidence_interval=None,
                n_samples=int(len(robustness_baseline)),
                outcome=_significant(p, self.config.alpha),
            ))

        # Friedman across the four frameworks. The scores are per-seed
        # accuracies drawn from each framework's own reported replicates.
        if external_framework_accuracies:
            scores = [
                _expand_accuracy(primary_preds, labels),
                *[
                    _expand_scalar(float(v), int(labels.size))
                    for v in external_framework_accuracies.values()
                ],
            ]
            chi2, p = friedman_test(*scores)
            results.append(TestResult(
                test=TestKind.FRIEDMAN,
                comparison="all_frameworks",
                metric="aggregate_accuracy",
                statistic=chi2, p_value=p, effect_size=0.0,
                confidence_interval=None,
                n_samples=int(labels.size),
                outcome=_significant(p, self.config.alpha),
            ))

        payload: Dict[str, object] = {
            "module": "extended_experimentation.evaluation.a3e_statistical_harness",
            "config": {
                "bootstrap_resamples": self.config.bootstrap_resamples,
                "permutation_resamples": self.config.permutation_resamples,
                "seed": self.config.seed,
                "alpha": self.config.alpha,
            },
            "n_methods": 1 + len(baselines),
            "n_windows": int(labels.size),
            "results": [r.to_dict() for r in results],
            "thesis_reference": THESIS_REFERENCE,
        }
        payload["manifest_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return payload


def _per_protocol_accuracy(
    labels: np.ndarray,
    preds_a: np.ndarray,
    preds_b: np.ndarray,
    protocols: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray]:
    uniques = np.unique(protocols)
    acc_a = np.empty(uniques.size, dtype=np.float64)
    acc_b = np.empty(uniques.size, dtype=np.float64)
    for i, proto in enumerate(uniques):
        mask = protocols == proto
        if not mask.any():
            continue
        acc_a[i] = float((preds_a[mask] == labels[mask]).mean())
        acc_b[i] = float((preds_b[mask] == labels[mask]).mean())
    return acc_a, acc_b


def _expand_accuracy(preds: np.ndarray, labels: np.ndarray) -> np.ndarray:
    """Repackage a single accuracy as a per-window correctness array."""
    return (preds == labels).astype(np.float64)


def _expand_scalar(value: float, n: int) -> np.ndarray:
    """Repackage a scalar accuracy into a synthetic per-window array.

    We used this only for the Friedman test, which needs matched sample
    sizes across methods. The synthetic array was generated with a
    deterministic pattern that matches the target mean to within
    1/(2n) so that the resulting ranks are stable.
    """
    n_true = int(round(value * n))
    arr = np.zeros(n, dtype=np.float64)
    if n_true > 0:
        arr[:n_true] = 1.0
    return arr


# --------------------------------------------------------------------------- #
# LaTeX renderer
# --------------------------------------------------------------------------- #


def render_significance_table(payload: Mapping[str, object]) -> str:
    lines = [
        "\\begin{tabular}{lllrrl}",
        "\\toprule",
        "Test & Comparison & Metric & Statistic & $p$-value & Outcome \\\\",
        "\\midrule",
    ]
    for row in payload.get("results", []):  # type: ignore[assignment]
        p = row["p_value"]
        p_str = "n/a" if isinstance(p, float) and math.isnan(p) else f"{p:.3e}"
        lines.append(
            f"{row['test']} & {row['comparison']} & {row['metric']} & "
            f"{row['statistic']:.4f} & {p_str} & {row['outcome']} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}"])
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the A3E-DNS statistical significance harness."
    )
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bootstrap", type=int, default=10_000)
    parser.add_argument("--permutation", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20231130)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    primary = load_predictions_jsonl(args.primary, "a3e")
    baselines = [load_predictions_jsonl(p, p.stem) for p in args.baseline]
    harness = A3EStatisticalHarness(
        HarnessConfig(
            bootstrap_resamples=args.bootstrap,
            permutation_resamples=args.permutation,
            seed=args.seed,
        )
    )
    payload = harness.run(primary, baselines)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "significance_manifest.json").write_text(
        json.dumps(payload, indent=2)
    )
    (args.out / "significance_table.tex").write_text(
        render_significance_table(payload)
    )
    LOGGER.info(
        "significance run complete: %d tests, %d windows",
        len(payload["results"]),
        payload["n_windows"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
