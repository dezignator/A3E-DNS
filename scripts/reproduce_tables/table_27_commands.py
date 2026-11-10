#!/usr/bin/env python3
"""Table 27 — Real-Time Implementation Commands and Operational Effects.

Reproduces the 5-row Table 27 from Chapter 6 (AEE Engine, QHE Module,
FL Coordinator, Anomaly Detector, Sandbox). The output JSON matches
``expected_outputs/table_27_expected.json`` exactly.

Note (thesis-internal inconsistency — see docs/LIMITATIONS.md §8):
Table 27's QHE command line lists ``-lattice-dimension 1024 -modulus
3329``; §6.5 specifies ``n = 256, q = 4096``. Both are reproduced
verbatim: this script emits the Table 27 command line as written in the
thesis.

Usage:
    python scripts/reproduce_tables/table_27_commands.py --mode toy
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
    p = argparse.ArgumentParser(prog="table_27_commands")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_27_expected.json"))
    return p.parse_args(argv)


#: Table 27 authoritative rows. Reproduced verbatim from Chapter 6.
ROWS = [
    {
        "component": "AEE Engine",
        "command": "aee-daemon start -mode adaptive -entropy-source /dev/urandom",
        "runtime_params": "Key rotation 10 s; entropy threshold ≥ 0.95",
        "performance_impact": "+0.2 ms latency; 37% security gain",
        "failover": "aee-fallback -scheme chacha20",
    },
    {
        "component": "QHE Module",
        "command": "qhe-service -lattice-dimension 1024 -modulus 3329 -parallel 8",
        "runtime_params": "Gaussian N(0, 1, 58)",
        "performance_impact": "+12% CPU; +256 MB mem",
        "failover": "qhe-degrade -level 512 -temporary",
    },
    {
        "component": "FL Coordinator",
        "command": "fl-coord -rounds 100 -clients 100 -dp-epsilon 0.7",
        "runtime_params": "Lap(0.1/0.7); geom. median",
        "performance_impact": "~1.2 MB/round bandwidth",
        "failover": "fl-isolate -client-id -threshold 3σ",
    },
    {
        "component": "Anomaly Detector",
        "command": "anomaly-detector -model transformer -layers 8 -heads 12",
        "runtime_params": "Window 512; adaptive thresholds",
        "performance_impact": "0.08 ms/query inference",
        "failover": "ensemble-fallback -models 3 -voting",
    },
    {
        "component": "Sandbox",
        "command": "sandbox-create -isolated -memory 2GB -timeout 30s",
        "runtime_params": "Traffic replication 3; full behavioral analysis",
        "performance_impact": "~15% resource overhead",
        "failover": "sandbox-kill -timeout -preserve-logs",
    },
]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = {
        "table": 27,
        "title": "Real-Time Implementation Commands and Operational Effects",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "rows": ROWS,
        "notes": [
            "QHE command line reproduced verbatim from Table 27.",
            "§6.5 specifies n=256, q=4096; the command line uses 1024/3329.",
            "The inconsistency is documented in docs/LIMITATIONS.md §8 and is not corrected here.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "table": 27, "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
