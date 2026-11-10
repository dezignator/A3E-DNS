#!/usr/bin/env python3
"""Table 34a — Closest Published Method per A³E-DNS Component (10 rows).

Reproduces the 10-row Table 34a from Chapter 6:

    1.  Advanced AEE
    2.  Optimized QHE
    3.  AI-Augmented FL
    4.  Integrated Threat Intel
    5.  Programmable Data Plane
    6.  Parallel Dataset Preprocessing
    7.  AMPS
    8.  Hardware Entropy
    9.  Neural Controller
    10. Composite

No row claims a new algorithm or a new cryptographic primitive. The
"What This Thesis Adds (Configuration)" column records the specific
parameterization, integration and evaluation conditions under which the
cited published method is used.

Usage:
    python scripts/reproduce_tables/table_34a_component_map.py --mode toy
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
    p = argparse.ArgumentParser(prog="table_34a_component_map")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_34a_expected.json"))
    return p.parse_args(argv)


ROWS = [
    {
        "component": "Advanced Adaptive Evolutionary Encryption (AEE)",
        "closest_published_method": "Module-LWE key encapsulation with SE(3) re-randomization [48,49,70]",
        "what_thesis_adds": (
            "Traffic-keyed schedule on SE(3)^n with hardware entropy; rotational "
            "component to key material, translational to IV and rotation cadence; "
            "diffusion coefficient bounded away from zero"
        ),
        "specified_evaluated": "§6.4, Eqs. (119)-(122); §6.16",
    },
    {
        "component": "Optimized Quantum-Safe Homomorphic Encryption (QHE)",
        "closest_published_method": "Ring-LWE encryption with NTT and AVX-512 batching [48,49,198,199]",
        "what_thesis_adds": (
            "Parameter set n=256, q=4096; selective operation set restricted to "
            "the statistical tests the detector needs; pipeline parallelization "
            "depth 3 on 16 cores"
        ),
        "specified_evaluated": "§6.5, Eqs. (123)-(125); §6.14",
    },
    {
        "component": "AI-Augmented Federated Learning (FL)",
        "closest_published_method": "Transformer with DP-SGD and geometric-median aggregation [128,181,182]",
        "what_thesis_adds": (
            "Spatio-temporal attention with temporal-decay encoding; min-max "
            "adversarial training with PGD; cross-checked aggregation against "
            "the topological detector"
        ),
        "specified_evaluated": "§6.6, Eqs. (126)-(130); §6.16",
    },
    {
        "component": "Integrated Threat Intelligence",
        "closest_published_method": "STIX/TAXII, honeypot/darknet telemetry, vendor feeds",
        "what_thesis_adds": "Operational integration into the A3E-DNS pipeline",
        "specified_evaluated": "§6.7, Table 28",
    },
    {
        "component": "Programmable Data Plane",
        "closest_published_method": "P4/BMv2 programmable switches",
        "what_thesis_adds": (
            "Three-stage protocol-specific metadata-extraction pipeline for "
            "DoH/DoT/DoQ"
        ),
        "specified_evaluated": "§6.12",
    },
    {
        "component": "Parallel Dataset Preprocessing",
        "closest_published_method": "Dask distributed computing",
        "what_thesis_adds": (
            "Encrypted-DNS-specific partitioning, feature engineering and label "
            "integration"
        ),
        "specified_evaluated": "§6.13",
    },
    {
        "component": "Adaptive Multi-Protocol Sandbox (AMPS)",
        "closest_published_method": "MDP and Hamilton-Jacobi-Bellman optimal control with protocol-specific isolation [99,187]",
        "what_thesis_adds": (
            "DoH stream termination, DoT TLS reset, DoQ connection migration; "
            "trigger by KL/Rényi divergence"
        ),
        "specified_evaluated": "§6.3.2, §6.17.3",
    },
    {
        "component": "Hardware Entropy",
        "closest_published_method": "RDRAND/RDSEED",
        "what_thesis_adds": "σ(t) = Ψ(D_KL(P_traffic ‖ P_baseline))",
        "specified_evaluated": "§6.4.3",
    },
    {
        "component": "Neural Controller",
        "closest_published_method": "Feedforward",
        "what_thesis_adds": "2×64 MLP, 1000-pkt window, RL reward",
        "specified_evaluated": "§6.4.5",
    },
    {
        "component": "Composite",
        "closest_published_method": "Harmonic mean + Eq. 131",
        "what_thesis_adds": "Eq. 131",
        "specified_evaluated": "§6.9.1",
    },
]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = {
        "table": "34a",
        "title": "Closest Published Method for Each A3E-DNS Component, With the Configuration Used Here and Where It Is Specified and Evaluated",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "n_components": len(ROWS),
        "rows": ROWS,
        "notes": [
            "No row in this table claims a new algorithm or a new cryptographic "
            "primitive. The 'what this thesis adds' column records the "
            "parameterization, integration and evaluation conditions under "
            "which the cited published method was used; the last column points "
            "to where each configuration is specified and where its "
            "contribution is measured.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": "ok",
        "table": "34a",
        "output": str(args.output),
        "n_components": len(ROWS),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
