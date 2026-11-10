#!/usr/bin/env python3
"""Table 30 — Attack Vector Taxonomy and Real-Time Countermeasures.

Reproduces the 6-row Table 30:

    1. Traffic Analysis     — Statistical Fingerprinting  (aee-morph)
    2. Tunneling            — DNS-over-DNS               (qhe-scan)
    3. Protocol Exploitation— QUIC Downgrade              (protocol-bind)
    4. ML Evasion           — Adversarial Query Crafting  (fl-train)
    5. Quantum Preparation  — Harvest-and-Decrypt         (qhe-rotate)
    6. Side-Channel         — Cache Timing                (dp-inject)

Usage:
    python scripts/reproduce_tables/table_30_taxonomy.py --mode toy
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="table_30_taxonomy")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_30_expected.json"))
    return p.parse_args(argv)


ROWS = [
    {
        "attack_class": "Traffic Analysis",
        "specific_attack": "Statistical Fingerprinting",
        "mechanism": "Timing inference; pktsize ∈ [256, 1400]",
        "framework_response": "AEE morphs timing Δt' = f(Δt, E(t))",
        "command": "aee-morph -protocol doh -window 100ms -entropy 0.9",
    },
    {
        "attack_class": "Tunneling",
        "specific_attack": "DNS-over-DNS",
        "mechanism": "Base64 subdomains",
        "framework_response": "QHE encrypted-domain pattern match",
        "command": "qhe-scan -encrypted-traffic -pattern-match -threshold 0.87",
    },
    {
        "attack_class": "Protocol Exploitation",
        "specific_attack": "QUIC Downgrade",
        "mechanism": "Manipulated transport params",
        "framework_response": "Adaptive protocol binding",
        "command": "protocol-bind -min-version quic-v1 -max-version quic-v2 -strict",
    },
    {
        "attack_class": "ML Evasion",
        "specific_attack": "Adversarial Query Crafting",
        "mechanism": "Q' = Q + ε·sign(∇_Q f(θ))",
        "framework_response": "Federated adversarial training (PGD)",
        "command": "fl-train -adversarial-epochs 50 -defense pgd -epsilon 0.3",
    },
    {
        "attack_class": "Quantum Preparation",
        "specific_attack": "Harvest-and-Decrypt",
        "mechanism": "Store now, decrypt later",
        "framework_response": "Lattice KEM + periodic rotation",
        "command": "qhe-rotate -scheme kyber1024 -interval 1h -post-quantum",
    },
    {
        "attack_class": "Side-Channel",
        "specific_attack": "Cache Timing",
        "mechanism": "σ² > 15 ms resolution variance",
        "framework_response": "DP noise t' = t + Lap(0.1/ε)",
        "command": "dp-inject -epsilon 0.7 -sensitivity 0.1 -mechanism laplacian",
    },
]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = {
        "table": 30,
        "title": "Attack Vector Taxonomy and Real-Time Countermeasures",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "n_classes": len(ROWS),
        "rows": ROWS,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "table": 30, "output": str(args.output),
                      "n_classes": len(ROWS)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
