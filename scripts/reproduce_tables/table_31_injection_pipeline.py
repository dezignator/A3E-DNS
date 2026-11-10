#!/usr/bin/env python3
"""Table 31 — Attack Injection Framework and Detection Pipeline.

Reproduces the 6-phase Table 31:

    Recon            — dnsenum               (rate-limit)
    Traffic Morphing — scapy-doh-morph       (aee-rekey)
    Encrypted Tunnel — iodine                (quarantine)
    Timing Attack    — time-doh-attack       (dp-enhance)
    Model Poisoning  — fl-poison             (fl-verify)
    QUIC Exploit     — quick-interop         (protocol-validate)

Usage:
    python scripts/reproduce_tables/table_31_injection_pipeline.py --mode toy
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
    p = argparse.ArgumentParser(prog="table_31_injection_pipeline")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_31_expected.json"))
    return p.parse_args(argv)


ROWS = [
    {
        "phase": "Recon",
        "command": "dnsenum -dnsserver 8.8.8.8 -enum",
        "observed_behavior": "~45 DNS q/s",
        "detection": "FL model, p = 0.82",
        "mitigation": "rate-limit -src-ip -queries 10/s",
    },
    {
        "phase": "Traffic Morphing",
        "command": "scapy-doh-morph -target resolver -shape gaussian",
        "observed_behavior": "μ = 900 B, σ = 150 B",
        "detection": "AEE dynamic threshold",
        "mitigation": "aee-rekey -trigger anomaly -strength high",
    },
    {
        "phase": "Encrypted Tunnel",
        "command": "iodine -f -P password 1.2.3.4 test.tunnel",
        "observed_behavior": "60 B @ 100 ms",
        "detection": "QHE: χ² = 45.6 > χ²_crit(α = 0.01)",
        "mitigation": "quarantine -flow -duration 5m -analyze",
    },
    {
        "phase": "Timing Attack",
        "command": "time-doh-attack -resolver target -samples 1000",
        "observed_behavior": "Response-time shift",
        "detection": "DP noise t' = t + N(0, 0.5)",
        "mitigation": "dp-enhance -sigma 0.5 -preserve-utility",
    },
    {
        "phase": "Model Poisoning",
        "command": "fl-poison -clients 5 -epsilon 0.3 -epochs 10",
        "observed_behavior": "δ = 0.15 adversarial bias",
        "detection": "MAD filter, MAD > 2.5σ",
        "mitigation": "fl-verify -median-filter -trim 0.1",
    },
    {
        "phase": "QUIC Exploit",
        "command": "quick-interop -version-spoof -force v1_draft",
        "observed_behavior": "Version mismatch",
        "detection": "Strict version binding",
        "mitigation": "protocol-validate -strict -rollback-on-fail",
    },
]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = {
        "table": 31,
        "title": "Attack Injection Framework and Detection Pipeline",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "n_phases": len(ROWS),
        "rows": ROWS,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "table": 31, "output": str(args.output),
                      "n_phases": len(ROWS)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
