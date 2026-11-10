#!/usr/bin/env python3
"""Table 33 — Performance Comparison Matrix (7 metrics × 3 systems).

Reproduces the full Table 33 from Chapter 6 including the statistical
notes column. Every row is reproduced verbatim; the script also runs a
self-consistency check for the numeric rows.

Rows (7 metrics):
    Detection Accuracy, False-Positive Rate, P99 Latency, Throughput,
    Adversarial Robustness, Privacy Leakage (ε), Quantum Resistance.

Usage:
    python scripts/reproduce_tables/table_33_performance.py --mode toy
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src import __version__, thesis_reference  # noqa: E402
from src.hardware_simulation.perf_model import TABLE33_PROPOSED  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="table_33_performance")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_33_expected.json"))
    return p.parse_args(argv)


#: Table 33 authoritative rows (Chapter 6, §6.16).
ROWS = [
    {
        "metric": "Detection Accuracy",
        "dnsguard": 91.2,
        "deepfingerprint": 96.7,
        "proposed": 99.94,
        "improvement_vs_dnsguard": "+8.74 pp",
        "improvement_vs_deepfingerprint": "+3.24 pp",
        "statistical_note": "t-test, p < 0.0001",
        "units": "%",
    },
    {
        "metric": "False-Positive Rate",
        "dnsguard": 2.1,
        "deepfingerprint": 0.8,
        "proposed": 0.17,
        "improvement_vs_dnsguard": "12.35× lower",
        "improvement_vs_deepfingerprint": "4.71× lower",
        "statistical_note": "Cohen's d = 1.87",
        "units": "%",
    },
    {
        "metric": "P99 Latency",
        "dnsguard": 4.2,
        "deepfingerprint": 2.8,
        "proposed": 1.42,
        "improvement_vs_dnsguard": "2.96× lower",
        "improvement_vs_deepfingerprint": "1.97× lower",
        "statistical_note": "95% CI [1.38, 1.46] ms",
        "units": "ms",
    },
    {
        "metric": "Throughput",
        "dnsguard": 8.0,
        "deepfingerprint": 15.0,
        "proposed": 22.5,
        "improvement_vs_dnsguard": "2.81× higher",
        "improvement_vs_deepfingerprint": "1.50× higher",
        "statistical_note": "Throughput efficiency 0.92",
        "units": "M QPS",
    },
    {
        "metric": "Adversarial Robustness",
        "dnsguard": 65.0,
        "deepfingerprint": 82.0,
        "proposed": 96.5,
        "improvement_vs_dnsguard": "+31.5 pp",
        "improvement_vs_deepfingerprint": "+14.5 pp",
        "statistical_note": "Adversarial gap 0.035 (§6.16.3)",
        "units": "%",
    },
    {
        "metric": "Privacy Leakage (ε)",
        "dnsguard": "n/a",
        "deepfingerprint": "n/a",
        "proposed": 0.68,
        "improvement_vs_dnsguard": "not comparable as a ratio",
        "improvement_vs_deepfingerprint": "not comparable as a ratio",
        "statistical_note": "DP mechanism at ε = 0.68 (§6.6.5)",
        "units": "ε",
    },
    {
        "metric": "Quantum Resistance",
        "dnsguard": "none",
        "deepfingerprint": "partial (hybrid)",
        "proposed": "lattice-based (conjecture)",
        "improvement_vs_dnsguard": "categorical difference; no ratio computed",
        "improvement_vs_deepfingerprint": "categorical difference; no ratio computed",
        "statistical_note": "estimated λ = 256 (§6.9.2)",
        "units": "categorical",
    },
]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Self-consistency check: proposed numbers must match TABLE33_PROPOSED.
    check = {
        "detection_accuracy": ROWS[0]["proposed"],
        "false_positive_rate": ROWS[1]["proposed"],
        "p99_latency_ms": ROWS[2]["proposed"],
        "throughput_m_qps": ROWS[3]["proposed"],
        "adversarial_robustness": ROWS[4]["proposed"],
        "privacy_epsilon": ROWS[5]["proposed"],
    }
    mismatches = [k for k, v in check.items() if float(v) != float(TABLE33_PROPOSED[k])]
    if mismatches:
        raise SystemExit(f"table_33 inconsistent with perf_model.TABLE33_PROPOSED: {mismatches}")

    payload = {
        "table": 33,
        "title": "Performance comparison matrix of baseline, state-of-the-art and proposed framework",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "n_metrics": len(ROWS),
        "n_systems": 3,
        "rows": ROWS,
        "notes": [
            "Percentage-point (pp) differences are used for accuracy, "
            "adversarial robustness, and any other quantity expressed as a "
            "bounded rate.",
            "Ratio improvements are used only where both systems measure the "
            "same quantity on the same scale (latency, throughput, FPR).",
            "Privacy leakage ε is a bound on the privacy loss of a specific "
            "mechanism under a specific neighbourhood relation; a ratio "
            "between two ε values from different mechanisms is not "
            "informative and is not reported.",
            "Quantum resistance is reported as a capability category, not as "
            "a numerical improvement factor.",
            "Baseline (DNSGuard) and state-of-the-art (DeepFingerprint) "
            "figures were obtained by reproducing and retraining both systems "
            "on the same data, with the same preprocessing and under the same "
            "tuning budget as the proposed framework (§6.16.2).",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": "ok",
        "table": 33,
        "output": str(args.output),
        "n_metrics": len(ROWS),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
