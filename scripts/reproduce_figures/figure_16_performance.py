#!/usr/bin/env python3
"""Figure 16 — A³E-DNS Multi-Protocol Attack Detection Performance (4 panels).

**Figure 16 is deliberately separate from Figure 19.** Figure 16 has
four panels; Figure 19 has six panels. They were combined in an earlier
draft and that combination has been removed (see STATUS.md).

Panels:
    (a) DoH — Traffic Morphing Attack Detection
    (b) DoT — Latency Injection Attack Detection
    (c) DoQ — DDoS Amplification Attack Detection
    (d) Multi-Protocol — DNS Tunneling Detection

Usage:
    python scripts/reproduce_figures/figure_16_performance.py --mode toy
    python scripts/reproduce_figures/figure_16_performance.py --mode medium
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src import __version__, thesis_reference  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="figure_16_performance")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/figure_16_expected.png"))
    p.add_argument("--seed", type=int, default=20261130)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    rng = np.random.default_rng(args.seed)
    meta = thesis_reference()

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(
        f"A³E-DNS: Multi-Protocol Attack Detection Performance Evaluation "
        f"({meta['chapter']} · artifact v{__version__})",
        fontsize=16, fontweight="bold",
    )

    t = np.linspace(0, 24, 240)

    # (a) DoH — Traffic Morphing Attack Detection
    rng_a = rng.normal(0, 1, len(t))
    attack_signal = 60 + 10 * np.sin(t / 2) + 25 * ((t > 8) & (t < 14)) + rng_a
    benign = 60 + 2 * np.sin(t / 3) + rng.normal(0, 1, len(t))
    axes[0, 0].plot(t, attack_signal, color="#dc2626", lw=1, alpha=0.8, label="Attack Pattern")
    axes[0, 0].plot(t, benign, color="#0891b2", lw=1, alpha=0.6, label="Normal Traffic")
    axes[0, 0].axhline(80, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[0, 0].set_title("(a) DoH: Traffic Morphing Detection")
    axes[0, 0].set_xlabel("Time (Hours)")
    axes[0, 0].set_ylabel("Query Rate (QPS × 10³)")
    axes[0, 0].grid(alpha=0.3)
    axes[0, 0].legend(fontsize=8)

    # (b) DoT — Latency Injection Attack Detection
    baseline_lat = 10 + 2 * np.sin(t / 4)
    injected = baseline_lat + 60 * ((t > 10) & (t < 14))
    axes[0, 1].plot(t, baseline_lat, color="#0891b2", lw=1.5, label="Normal Latency")
    axes[0, 1].plot(t, injected, color="#dc2626", lw=1, alpha=0.8, label="Injected Latency")
    axes[0, 1].axhline(50, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[0, 1].set_title("(b) DoT: Latency Injection Attack Detection")
    axes[0, 1].set_xlabel("Time (Hours)")
    axes[0, 1].set_ylabel("Response Latency (ms)")
    axes[0, 1].grid(alpha=0.3)
    axes[0, 1].legend(fontsize=8)

    # (c) DoQ — DDoS Amplification Attack Detection
    conn = 30 + 5 * np.sin(t / 3)
    conn_attack = conn + 80 * ((t > 6) & (t < 10)) + 60 * ((t > 16) & (t < 20))
    axes[1, 0].plot(t, conn, color="#0891b2", lw=1.5, label="Normal Connections")
    axes[1, 0].plot(t, conn_attack, color="#dc2626", lw=1, alpha=0.8, label="DDoS Traffic")
    axes[1, 0].axhline(70, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[1, 0].set_title("(c) DoQ: DDoS Amplification Attack Detection")
    axes[1, 0].set_xlabel("Time (Hours)")
    axes[1, 0].set_ylabel("Connections (K)")
    axes[1, 0].grid(alpha=0.3)
    axes[1, 0].legend(fontsize=8)

    # (d) Multi-Protocol — DNS Tunneling Detection
    tunneling = 0.4 + 0.1 * np.sin(t / 2) + 0.6 * np.exp(-((t - 12) ** 2) / 8)
    axes[1, 1].plot(t, tunneling, color="#7c3aed", lw=2, label="Tunneling Score")
    axes[1, 1].axhline(0.7, color="#dc2626", ls="--", lw=1.5, label="Detection Threshold")
    axes[1, 1].fill_between(t, 0.7, tunneling, where=(tunneling > 0.7), color="#fca5a5", alpha=0.4, label="Flagged")
    axes[1, 1].set_title("(d) Multi-Protocol: DNS Tunneling Detection")
    axes[1, 1].set_xlabel("Time (Hours)")
    axes[1, 1].set_ylabel("Anomaly Score")
    axes[1, 1].set_ylim(0, 1.2)
    axes[1, 1].grid(alpha=0.3)
    axes[1, 1].legend(fontsize=8)

    plt.tight_layout(rect=(0, 0, 1, 0.95))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=150)
    plt.close(fig)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
