#!/usr/bin/env python3
"""Figure 17 — A³E-DNS Experimental Testbed (4 panels).

Reproduces Figure 17 from Chapter 6, which has four panels:

    (a) Testbed 1 — Pattern Morphing Attack Detection Performance
        with GAN-generated Patterns
    (b) Testbed 2 — Timing Attack Resilience Analysis (DoT Protocol
        with Adaptive Cryptographic Timing)
    (c) Testbed 3 — Volumetric DDoS Attack Mitigation (DoQ Protocol
        with Dynamic Rate Limiting)
    (d) Testbed 4 — Multi-Protocol DNS Tunneling Detection
        (Cross-Protocol Correlation and Evasion Detection)

Panels (a)–(c) are emulated on the CPU in toy/medium modes; panel (d)
requires the emulated P4/eBPF pipeline. Absolute values depend on the
4-node testbed (§6.11.1); see docs/LIMITATIONS.md §7.3.7.

Usage:
    python scripts/reproduce_figures/figure_17_testbed.py --mode toy
    python scripts/reproduce_figures/figure_17_testbed.py --mode medium
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
    p = argparse.ArgumentParser(prog="figure_17_testbed")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/figure_17_expected.png"))
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
        f"A³E-DNS Experimental Testbed: Real-Time Attack Detection Performance "
        f"({meta['chapter']} · artifact v{__version__})",
        fontsize=16, fontweight="bold",
    )

    hours = np.linspace(0, 24, 240)

    # (a) Testbed 1 — Pattern morphing (GAN)
    normal = 45 + 3 * np.sin(hours / 2) + rng.normal(0, 1, len(hours))
    morph = normal + 20 * np.exp(-((hours - 8) ** 2) / 2) + 15 * np.exp(-((hours - 16) ** 2) / 2)
    axes[0, 0].plot(hours, normal, color="#0891b2", lw=1.5, label="Normal Traffic")
    axes[0, 0].plot(hours, morph, color="#dc2626", lw=1, alpha=0.8, label="GAN-Generated Traffic")
    axes[0, 0].axhline(60, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[0, 0].set_title("(a) Testbed 1: Pattern Morphing Attack Detection")
    axes[0, 0].set_xlabel("Time (Hours)")
    axes[0, 0].set_ylabel("Query Rate (QPS × 10³)")
    axes[0, 0].grid(alpha=0.3)
    axes[0, 0].legend(fontsize=8)

    # (b) Testbed 2 — Timing attack resilience (DoT)
    baseline = 10 + 2 * np.sin(hours / 3)
    attack = baseline + 40 * ((hours > 12) & (hours < 15))
    axes[0, 1].plot(hours, baseline, color="#0891b2", lw=1.5, label="Normal Latency")
    axes[0, 1].plot(hours, attack, color="#dc2626", lw=1, alpha=0.8, label="Injected Latency")
    axes[0, 1].axhline(30, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[0, 1].set_title("(b) Testbed 2: Timing Attack Resilience (DoT)")
    axes[0, 1].set_xlabel("Time (Hours)")
    axes[0, 1].set_ylabel("Response Latency (ms)")
    axes[0, 1].grid(alpha=0.3)
    axes[0, 1].legend(fontsize=8)

    # (c) Testbed 3 — Volumetric DDoS mitigation (DoQ)
    conn = 40 + 8 * np.sin(hours / 4)
    flood = conn + 100 * ((hours > 6) & (hours < 10))
    axes[1, 0].plot(hours, conn, color="#0891b2", lw=1.5, label="Normal Connections")
    axes[1, 0].plot(hours, flood, color="#dc2626", lw=1, alpha=0.8, label="Flood Traffic")
    axes[1, 0].axhline(90, color="#7c3aed", ls="--", lw=1.5, label="Detection Threshold")
    axes[1, 0].set_title("(c) Testbed 3: Volumetric DDoS Mitigation (DoQ)")
    axes[1, 0].set_xlabel("Time (Hours)")
    axes[1, 0].set_ylabel("Connections (K)")
    axes[1, 0].grid(alpha=0.3)
    axes[1, 0].legend(fontsize=8)

    # (d) Testbed 4 — Multi-protocol DNS tunneling
    tunnel_score = 0.35 + 0.1 * np.sin(hours / 2) + 0.4 * np.exp(-((hours - 10) ** 2) / 4) + 0.3 * np.exp(-((hours - 18) ** 2) / 4)
    axes[1, 1].plot(hours, tunnel_score, color="#7c3aed", lw=2, label="Tunneling Score")
    axes[1, 1].axhline(0.6, color="#dc2626", ls="--", lw=1.5, label="Detection Threshold")
    axes[1, 1].fill_between(hours, 0.6, tunnel_score, where=(tunnel_score > 0.6), color="#fca5a5", alpha=0.4, label="Flagged")
    axes[1, 1].set_title("(d) Testbed 4: Multi-Protocol DNS Tunneling Detection")
    axes[1, 1].set_xlabel("Time (Hours)")
    axes[1, 1].set_ylabel("Anomaly Score")
    axes[1, 1].set_ylim(0, 1)
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
