#!/usr/bin/env python3
"""
extended_experimentation/evaluation/a3e_ablation_runner.py

Component ablation runner for the A3E-DNS Chapter 6 evaluation.

We implemented this module to run the five-way ablation the thesis
reports in E7 and Table 36. The five variants are:

  * full         — the complete A3E-DNS system,
  * no_aee       — AEE replaced by a static key schedule,
  * no_qhe       — QHE replaced by plaintext computation,
  * no_fl        — centralized training on pooled client data,
  * no_attention — attention block replaced by a flat MLP head.

The runner consumes the checkpoint directories produced by the training
pipeline when each variant was trained, and does not retrain. That design
was deliberate and identical to the one we applied in the MIRAGE-DoH
ablation runner: a re-train during ablation would have conflated the
component effect with the training seed effect, and the ablation claim in
the thesis is about the component, not about a run-to-run difference.

Each variant directory is expected to contain either a ``metrics.json``
or a ``core_metrics.json`` with the confusion matrix and latency
percentiles. The runner normalises both shapes to the same internal
MetricSnapshot. It then computes the delta against the full variant and
classifies the delta as material or not, using thresholds that we fixed
before running the ablation so that we could not be tempted to loosen
them when a variant turned out worse than expected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.ablation")

# --------------------------------------------------------------------------- #
# Thesis reference
# --------------------------------------------------------------------------- #

THESIS_REFERENCE: Dict[str, float] = {
    "detection_accuracy": 0.9994,
    "false_positive_rate_fraction": 0.0017,
    "p99_latency_ms": 1.42,
    "peak_throughput_qps": 22_500_000,
}

# --------------------------------------------------------------------------- #
# Variant definitions
# --------------------------------------------------------------------------- #

VARIANT_DESCRIPTIONS: Dict[str, str] = {
    "full": "Complete A3E-DNS reference implementation.",
    "no_aee": "AEE replaced by a static key schedule.",
    "no_qhe": "QHE replaced by plaintext computation on the same features.",
    "no_fl": "Centralized training on pooled client data.",
    "no_attention": "Attention block replaced by a flat MLP head.",
}

# Material-regression thresholds, frozen before ablation.
MATERIAL_ACCURACY_DROP = 0.002
MATERIAL_FPR_INCREASE = 0.0005
MATERIAL_P99_INCREASE_MS = 0.20

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class VariantStatus(str, Enum):
    COMPLETED = "completed"
    MISSING = "missing"
    FAILED = "failed"


class RegressionClass(str, Enum):
    NONE = "none"
    ACCURACY = "accuracy"
    FPR = "fpr"
    LATENCY = "latency"
    ACCURACY_AND_FPR = "accuracy_and_fpr"
    MULTIPLE = "multiple"


# --------------------------------------------------------------------------- #
# Snapshot and delta
# --------------------------------------------------------------------------- #


@dataclass
class MetricSnapshot:
    variant: str
    detection_accuracy: float
    false_positive_rate_fraction: float
    p99_latency_ms: float
    throughput_qps: float
    status: VariantStatus
    source_file: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "variant": self.variant,
            "description": VARIANT_DESCRIPTIONS.get(self.variant, ""),
            "detection_accuracy": self.detection_accuracy,
            "false_positive_rate_fraction": self.false_positive_rate_fraction,
            "p99_latency_ms": self.p99_latency_ms,
            "throughput_qps": self.throughput_qps,
            "status": self.status.value,
            "source_file": self.source_file,
        }


@dataclass
class AblationDelta:
    variant: str
    accuracy_delta: float
    fpr_delta: float
    latency_delta_ms: float
    throughput_delta_qps: float
    regression_class: RegressionClass

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def _load_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        LOGGER.warning("could not parse %s", path)
        return None


def _normalise_metrics(payload: Mapping[str, object]) -> Dict[str, float]:
    """Flatten either a metrics envelope or a flat dict to the same keys."""
    source = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else payload
    out: Dict[str, float] = {}
    mapping = {
        "detection_accuracy": ["detection_accuracy", "accuracy"],
        "false_positive_rate_fraction": [
            "false_positive_rate_fraction", "fpr", "false_positive_rate"
        ],
        "p99_latency_ms": ["p99_latency_ms", "p99_latency", "latency_p99_ms"],
        "throughput_qps": ["throughput_qps", "peak_throughput_qps", "qps"],
    }
    for target, candidates in mapping.items():
        for key in candidates:
            if key in source:  # type: ignore[operator]
                try:
                    out[target] = float(source[key])  # type: ignore[index]
                    break
                except (TypeError, ValueError):
                    continue
    return out


def _load_variant_snapshot(variant_root: Path, variant: str) -> MetricSnapshot:
    for candidate in ("core_metrics.json", "metrics.json"):
        path = variant_root / candidate
        if path.exists():
            payload = _load_json(path)
            if payload is None:
                continue
            values = _normalise_metrics(payload)
            return MetricSnapshot(
                variant=variant,
                detection_accuracy=values.get("detection_accuracy", 0.0),
                false_positive_rate_fraction=values.get(
                    "false_positive_rate_fraction", 0.0
                ),
                p99_latency_ms=values.get("p99_latency_ms", 0.0),
                throughput_qps=values.get("throughput_qps", 0.0),
                status=VariantStatus.COMPLETED,
                source_file=str(path),
            )
    return MetricSnapshot(
        variant=variant,
        detection_accuracy=0.0,
        false_positive_rate_fraction=0.0,
        p99_latency_ms=0.0,
        throughput_qps=0.0,
        status=VariantStatus.MISSING,
        source_file=None,
    )


# --------------------------------------------------------------------------- #
# Delta computation
# --------------------------------------------------------------------------- #


def _classify_regression(
    accuracy_delta: float, fpr_delta: float, latency_delta_ms: float
) -> RegressionClass:
    acc = accuracy_delta <= -MATERIAL_ACCURACY_DROP
    fpr = fpr_delta >= MATERIAL_FPR_INCREASE
    lat = latency_delta_ms >= MATERIAL_P99_INCREASE_MS
    if acc and fpr and lat:
        return RegressionClass.MULTIPLE
    if acc and fpr:
        return RegressionClass.ACCURACY_AND_FPR
    if acc:
        return RegressionClass.ACCURACY
    if fpr:
        return RegressionClass.FPR
    if lat:
        return RegressionClass.LATENCY
    return RegressionClass.NONE


def _compute_delta(baseline: MetricSnapshot, variant: MetricSnapshot) -> AblationDelta:
    return AblationDelta(
        variant=variant.variant,
        accuracy_delta=variant.detection_accuracy - baseline.detection_accuracy,
        fpr_delta=(
            variant.false_positive_rate_fraction
            - baseline.false_positive_rate_fraction
        ),
        latency_delta_ms=variant.p99_latency_ms - baseline.p99_latency_ms,
        throughput_delta_qps=variant.throughput_qps - baseline.throughput_qps,
        regression_class=_classify_regression(
            accuracy_delta=variant.detection_accuracy - baseline.detection_accuracy,
            fpr_delta=(
                variant.false_positive_rate_fraction
                - baseline.false_positive_rate_fraction
            ),
            latency_delta_ms=variant.p99_latency_ms - baseline.p99_latency_ms,
        ),
    )


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


@dataclass
class AblationConfig:
    variants: Tuple[str, ...] = (
        "full", "no_aee", "no_qhe", "no_fl", "no_attention",
    )
    seed: int = 20231130


class A3EAblationRunner:
    def __init__(self, config: Optional[AblationConfig] = None) -> None:
        self.config = config or AblationConfig()

    def run(self, checkpoint_root: Path) -> Dict[str, object]:
        root = Path(checkpoint_root)
        snapshots: Dict[str, MetricSnapshot] = {}
        for variant in self.config.variants:
            variant_root = root / variant
            if not variant_root.exists():
                snapshots[variant] = MetricSnapshot(
                    variant=variant,
                    detection_accuracy=0.0,
                    false_positive_rate_fraction=0.0,
                    p99_latency_ms=0.0,
                    throughput_qps=0.0,
                    status=VariantStatus.MISSING,
                )
                continue
            snapshots[variant] = _load_variant_snapshot(variant_root, variant)

        baseline = snapshots.get("full")
        if baseline is None or baseline.status is not VariantStatus.COMPLETED:
            raise RuntimeError(
                "the 'full' variant must be present and valid; other variants "
                "are optional but the delta cannot be computed without a baseline"
            )

        deltas: List[AblationDelta] = []
        for variant, snap in snapshots.items():
            if variant == "full":
                continue
            if snap.status is not VariantStatus.COMPLETED:
                continue
            deltas.append(_compute_delta(baseline, snap))

        regressed = [
            d for d in deltas if d.regression_class is not RegressionClass.NONE
        ]
        payload: Dict[str, object] = {
            "module": "extended_experimentation.evaluation.a3e_ablation_runner",
            "n_variants": len(self.config.variants),
            "n_completed": sum(
                1 for s in snapshots.values()
                if s.status is VariantStatus.COMPLETED
            ),
            "snapshots": [s.to_dict() for s in snapshots.values()],
            "deltas": [d.to_dict() for d in deltas],
            "n_regressed": len(regressed),
            "thresholds": {
                "accuracy_drop": MATERIAL_ACCURACY_DROP,
                "fpr_increase": MATERIAL_FPR_INCREASE,
                "p99_increase_ms": MATERIAL_P99_INCREASE_MS,
            },
            "thesis_reference": THESIS_REFERENCE,
            "notes": (
                "Partial ablation only. A full factorial design was not "
                "performed; see Section 6.7.3 of the thesis."
            ),
        }
        payload["manifest_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return payload


# --------------------------------------------------------------------------- #
# LaTeX table
# --------------------------------------------------------------------------- #


def render_ablation_table(payload: Mapping[str, object]) -> str:
    lines = [
        "\\begin{tabular}{lrrrl}",
        "\\toprule",
        "Variant & Accuracy & FPR & P99 (ms) & Regression \\\\",
        "\\midrule",
    ]
    deltas_by_variant = {d["variant"]: d for d in payload.get("deltas", [])}
    for snap in payload.get("snapshots", []):  # type: ignore[assignment]
        name = str(snap["variant"])
        verdict = deltas_by_variant.get(name, {}).get("regression_class", "reference")
        lines.append(
            f"{name} & {snap['detection_accuracy']:.6f} & "
            f"{snap['false_positive_rate_fraction']:.6f} & "
            f"{snap['p99_latency_ms']:.3f} & {verdict} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}"])
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the A3E-DNS component ablation study."
    )
    parser.add_argument("--checkpoint-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    runner = A3EAblationRunner()
    payload = runner.run(args.checkpoint_root)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ablation_manifest.json").write_text(
        json.dumps(payload, indent=2)
    )
    (args.out / "ablation_table.tex").write_text(render_ablation_table(payload))
    LOGGER.info(
        "ablation complete: %d completed, %d regressed",
        payload["n_completed"], payload["n_regressed"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
