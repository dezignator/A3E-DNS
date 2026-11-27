#!/usr/bin/env python3
"""
extended_experimentation/reporting/a3e_figures.py

Figure reproducer for the A3E-DNS Chapter 6 evaluation.

We implemented this module to regenerate the seven data figures that
accompany the extended experiments. The figures are:

  F1  Detection accuracy as a function of attack severity.
  F2  Byzantine robustness vs Byzantine fraction.
  F3  DP epsilon vs utility trade-off.
  F4  Latency CDF by protocol.
  F5  Throughput vs concurrency.
  F6  QHE NTT speedup.
  F7  Multi-protocol accuracy comparison.

Matplotlib is optional. If it is unavailable, the module still writes
the underlying data in a compressed NumPy archive so that the figures can
be re-rendered elsewhere. That two-tier approach mirrors the one we used
in the MIRAGE-DoH figure reproducer and the reasoning is the same: the
thesis's reproducibility claim rests on the data, not on the figure
having been rendered on the examiner's host.

The figure reproducer never mutates the input manifests. It reads them,
projects them into plotting primitives, and writes the outputs to a
directory the caller owns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.figures")

# --------------------------------------------------------------------------- #
# Optional matplotlib
# --------------------------------------------------------------------------- #

try:  # pragma: no cover
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except Exception:  # pragma: no cover
    plt = None  # type: ignore[assignment]
    _HAS_MPL = False

# --------------------------------------------------------------------------- #
# Thesis reference
# --------------------------------------------------------------------------- #

THESIS_REFERENCE: Dict[str, float] = {
    "detection_accuracy": 0.9994,
    "false_positive_rate_fraction": 0.0017,
    "p99_latency_ms": 1.42,
    "peak_throughput_qps": 22_500_000,
    "adversarial_robustness": 0.965,
    "differential_privacy_epsilon": 0.68,
}

# --------------------------------------------------------------------------- #
# Figure specs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FigureSpec:
    name: str
    title: str
    width_in: float = 6.0
    height_in: float = 4.0
    dpi: int = 150


FIGURES: Dict[str, FigureSpec] = {
    "F1": FigureSpec(name="F1", title="Detection accuracy vs. attack severity"),
    "F2": FigureSpec(name="F2", title="Byzantine robustness vs. Byzantine fraction"),
    "F3": FigureSpec(name="F3", title="DP epsilon vs. utility"),
    "F4": FigureSpec(name="F4", title="Latency CDF by protocol"),
    "F5": FigureSpec(name="F5", title="Throughput vs. concurrency"),
    "F6": FigureSpec(name="F6", title="QHE NTT vs. convolution speedup"),
    "F7": FigureSpec(name="F7", title="Multi-protocol accuracy"),
}

# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def _load_json(path: Path) -> Optional[Dict[str, object]]:
    if not path.exists():
        LOGGER.warning("missing manifest %s", path)
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        LOGGER.exception("failed to parse %s", path)
        return None


# --------------------------------------------------------------------------- #
# Data extractors
# --------------------------------------------------------------------------- #


def _extract_f1(scenario_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not scenario_manifest:
        return {"severities": [], "accuracies": []}
    rows = scenario_manifest.get("scenarios", [])
    sev: List[float] = []
    acc: List[float] = []
    for r in rows:  # type: ignore[assignment]
        sev.append(float(r.get("severity", 0.0)))
        acc.append(float(r.get("accuracy", 0.0)))
    order = np.argsort(sev)
    return {
        "severities": [sev[int(i)] for i in order],
        "accuracies": [acc[int(i)] for i in order],
    }


def _extract_f2(byz_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not byz_manifest:
        return {"fractions": [], "mean_ratios": [], "max_ratios": []}
    rows = byz_manifest.get("sweep", [])
    return {
        "fractions": [float(r.get("byzantine_fraction", 0.0)) for r in rows],  # type: ignore[union-attr]
        "mean_ratios": [
            float(r.get("mean_attack_to_reference_ratio", 0.0)) for r in rows  # type: ignore[union-attr]
        ],
        "max_ratios": [
            float(r.get("max_attack_to_reference_ratio", 0.0)) for r in rows  # type: ignore[union-attr]
        ],
    }


def _extract_f3(dp_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not dp_manifest:
        return {"epsilons": [], "accuracies": [], "fprs": []}
    rows = dp_manifest.get("sweep", [])
    return {
        "epsilons": [float(r.get("epsilon", 0.0)) for r in rows],  # type: ignore[union-attr]
        "accuracies": [float(r.get("accuracy", 0.0)) for r in rows],  # type: ignore[union-attr]
        "fprs": [float(r.get("fpr", 0.0)) for r in rows],  # type: ignore[union-attr]
    }


def _extract_f4(latency_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not latency_manifest:
        return {"protocols": [], "percentiles": {}}
    by_proto = latency_manifest.get("by_protocol", {})
    protocols: List[str] = []
    percentiles: Dict[str, Dict[str, float]] = {}
    for proto, bucket in (by_proto or {}).items():  # type: ignore[union-attr]
        protocols.append(str(proto))
        percentiles[str(proto)] = {
            "median": float(bucket.get("median_ms", 0.0)),
            "p95": float(bucket.get("p95_ms", 0.0)),
            "p99": float(bucket.get("p99_ms", 0.0)),
        }
    return {"protocols": protocols, "percentiles": percentiles}


def _extract_f5(throughput_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not throughput_manifest:
        return {"concurrency": [], "qps": []}
    rows = throughput_manifest.get("sweep", [])
    return {
        "concurrency": [int(r.get("concurrency", 0)) for r in rows],  # type: ignore[union-attr]
        "qps": [float(r.get("qps", 0.0)) for r in rows],  # type: ignore[union-attr]
    }


def _extract_f6(ntt_manifest: Optional[Mapping[str, object]]) -> Dict[str, float]:
    if not ntt_manifest:
        return {}
    ntt = ntt_manifest.get("ntt_vs_convolution", {})
    if not isinstance(ntt, dict):
        return {}
    return {
        "ntt_median_ms": float(ntt.get("ntt_median_ms", 0.0)),
        "convolution_median_ms": float(ntt.get("convolution_median_ms", 0.0)),
        "speedup": float(ntt.get("speedup", 0.0)),
    }


def _extract_f7(multi_manifest: Optional[Mapping[str, object]]) -> Dict[str, object]:
    if not multi_manifest:
        return {"protocols": [], "accuracies": []}
    by_proto = multi_manifest.get("by_protocol", {})
    protocols: List[str] = []
    accs: List[float] = []
    for proto, bucket in (by_proto or {}).items():  # type: ignore[union-attr]
        protocols.append(str(proto))
        accs.append(float(bucket.get("accuracy", 0.0)))
    return {"protocols": protocols, "accuracies": accs}


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #


def _render_f1(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("severities"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    ax.plot(data["severities"], data["accuracies"], marker="o", color="#2c3e50")  # type: ignore[arg-type]
    ax.axhline(
        THESIS_REFERENCE["detection_accuracy"],
        color="red", linestyle="--", linewidth=1.0,
        label="thesis reference",
    )
    ax.set_xlabel("Attack severity")
    ax.set_ylabel("Detection accuracy")
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f2(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("fractions"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    ax.plot(data["fractions"], data["mean_ratios"], marker="o", label="mean", color="#2980b9")  # type: ignore[arg-type]
    ax.plot(data["fractions"], data["max_ratios"], marker="s", label="max", color="#c0392b")  # type: ignore[arg-type]
    ax.set_xlabel("Byzantine fraction")
    ax.set_ylabel("Attack-to-reference ratio")
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f3(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("epsilons"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    ax.plot(data["epsilons"], data["accuracies"], marker="o", label="accuracy", color="#27ae60")  # type: ignore[arg-type]
    ax.plot(data["epsilons"], data["fprs"], marker="x", label="FPR", color="#8e44ad")  # type: ignore[arg-type]
    ax.axvline(
        THESIS_REFERENCE["differential_privacy_epsilon"],
        color="red", linestyle="--", linewidth=1.0, label="thesis ε",
    )
    ax.set_xlabel("DP ε")
    ax.set_ylabel("Metric value")
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f4(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("percentiles"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    percentiles = data["percentiles"]  # type: ignore[assignment]
    xs = np.array([50.0, 95.0, 99.0])
    for proto, vals in percentiles.items():  # type: ignore[union-attr]
        ys = np.array([vals["median"], vals["p95"], vals["p99"]])
        ax.plot(xs, ys, marker="o", label=str(proto))
    ax.axhline(
        THESIS_REFERENCE["p99_latency_ms"],
        color="red", linestyle="--", linewidth=1.0, label="thesis P99",
    )
    ax.set_xlabel("Percentile")
    ax.set_ylabel("Latency (ms)")
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f5(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("concurrency"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    ax.plot(data["concurrency"], data["qps"], marker="o", color="#16a085")  # type: ignore[arg-type]
    ax.axhline(
        THESIS_REFERENCE["peak_throughput_qps"],
        color="red", linestyle="--", linewidth=1.0, label="thesis peak",
    )
    ax.set_xlabel("Concurrency")
    ax.set_ylabel("Throughput (QPS)")
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f6(data: Mapping[str, float], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data:
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    names = ["NTT", "Convolution"]
    values = [data.get("ntt_median_ms", 0.0), data.get("convolution_median_ms", 0.0)]
    ax.bar(names, values, color=["#3498db", "#e67e22"])
    ax.set_ylabel("Median time (ms)")
    ax.set_title(f"{spec.title} (speedup {data.get('speedup', 0.0):.2f}x)")
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


def _render_f7(data: Mapping[str, object], spec: FigureSpec, out: Path) -> None:
    if not _HAS_MPL or not data.get("protocols"):
        return
    fig, ax = plt.subplots(figsize=(spec.width_in, spec.height_in))
    xs = np.arange(len(data["protocols"]))  # type: ignore[arg-type]
    ax.bar(xs, data["accuracies"], color="#2980b9")  # type: ignore[arg-type]
    ax.set_xticks(xs)
    ax.set_xticklabels([str(p).upper() for p in data["protocols"]])  # type: ignore[arg-type]
    ax.axhline(
        THESIS_REFERENCE["detection_accuracy"],
        color="red", linestyle="--", linewidth=1.0, label="thesis reference",
    )
    ax.set_ylabel("Accuracy")
    ax.set_ylim(0.99, 1.001)
    ax.set_title(spec.title)
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out / f"figure_{spec.name}.png", dpi=spec.dpi)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def reproduce_figures(
    manifests_root: Path,
    out_dir: Path,
) -> Dict[str, object]:
    root = Path(manifests_root)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    scenario = _load_json(root / "E1" / "scenario_sweep.json")
    byz = _load_json(root / "E2" / "byzantine_sweep.json")
    dp = _load_json(root / "E3" / "dp_sweep.json")
    latency = _load_json(root / "E5" / "latency.json")
    throughput = _load_json(root / "E6" / "throughput.json")
    ntt = _load_json(root / "E4a" / "ntt_benchmark.json")
    multi = _load_json(root / "E8" / "multi_protocol.json")

    f1 = _extract_f1(scenario)
    f2 = _extract_f2(byz)
    f3 = _extract_f3(dp)
    f4 = _extract_f4(latency)
    f5 = _extract_f5(throughput)
    f6 = _extract_f6(ntt)
    f7 = _extract_f7(multi)

    _render_f1(f1, FIGURES["F1"], out)
    _render_f2(f2, FIGURES["F2"], out)
    _render_f3(f3, FIGURES["F3"], out)
    _render_f4(f4, FIGURES["F4"], out)
    _render_f5(f5, FIGURES["F5"], out)
    _render_f6(f6, FIGURES["F6"], out)
    _render_f7(f7, FIGURES["F7"], out)

    np.savez_compressed(
        out / "figure_data.npz",
        f1_severities=np.asarray(f1.get("severities", []), dtype=np.float64),
        f1_accuracies=np.asarray(f1.get("accuracies", []), dtype=np.float64),
        f2_fractions=np.asarray(f2.get("fractions", []), dtype=np.float64),
        f2_mean_ratios=np.asarray(f2.get("mean_ratios", []), dtype=np.float64),
        f3_epsilons=np.asarray(f3.get("epsilons", []), dtype=np.float64),
        f4_protocols=np.asarray(f4.get("protocols", []), dtype=object),
        f5_concurrency=np.asarray(f5.get("concurrency", []), dtype=np.float64),
        f5_qps=np.asarray(f5.get("qps", []), dtype=np.float64),
        f7_protocols=np.asarray(f7.get("protocols", []), dtype=object),
        f7_accuracies=np.asarray(f7.get("accuracies", []), dtype=np.float64),
    )

    manifest: Dict[str, object] = {
        "module": "extended_experimentation.reporting.a3e_figures",
        "matplotlib_available": _HAS_MPL,
        "figures": {
            name: {
                "title": spec.title,
                "png_file": f"figure_{name}.png" if _HAS_MPL else None,
            }
            for name, spec in FIGURES.items()
        },
        "thesis_reference": THESIS_REFERENCE,
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    (out / "figures_manifest.json").write_text(json.dumps(manifest, indent=2))

    if not _HAS_MPL:
        LOGGER.warning(
            "matplotlib unavailable; wrote figure data only to %s",
            out / "figure_data.npz",
        )
    else:
        LOGGER.info("wrote figures F1-F7 to %s", out)
    return manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reproduce the A3E-DNS F1-F7 data figures."
    )
    parser.add_argument("--manifests-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    reproduce_figures(args.manifests_root, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
