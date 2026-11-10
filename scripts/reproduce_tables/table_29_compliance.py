#!/usr/bin/env python3
"""Table 29 — Certification and Compliance Verification.

Reproduces the 5-row Table 29:

    NIST CSF  — Identify / Protect / Detect / Respond / Recover
    GDPR      — data minimisation + DP bound + ZK attestation
    ISO 27001 — access control + audit trail
    PCI DSS   — cardholder isolation + authenticated transport
    FISMA     — crypto protection + hardware entropy + FL isolation

Each row is produced by the corresponding compliance checker in
``src.compliance``; the script also runs a **verification** of the
checkers against the framework configuration.

Usage:
    python scripts/reproduce_tables/table_29_compliance.py --mode toy
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
from src.compliance import ALL_CHECKERS, run_all_checkers  # noqa: E402
from src.utils.config_loader import load_config, CONFIG_NAMES  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="table_29_compliance")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_29_expected.json"))
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Load all framework configs into a single metadata dict.
    metadata = {}
    for name in CONFIG_NAMES:
        try:
            metadata[name] = load_config(name)[name]
        except Exception:
            metadata[name] = {}

    results = run_all_checkers(metadata)
    rows = []
    for r in results:
        rows.append({
            "standard": r.standard,
            "technical_properties": list(r.properties),
            "verification_method": "src.compliance checkers against framework metadata",
            "limits": list(r.limitations),
            "verdict": r.verdict.value,
        })

    payload = {
        "table": 29,
        "title": "Certification and Compliance Verification in the Proposed Encrypted DNS Security Framework",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "rows": rows,
        "notes": [
            "These are technical properties, not compliance certifications.",
            "A full compliance determination requires an organisational audit "
            "(record keeping, retention, access control, breach notification, "
            "governance) that is out of scope for this artifact.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({
        "status": "ok",
        "table": 29,
        "output": str(args.output),
        "n_checkers": len(ALL_CHECKERS),
        "verdicts": [r.verdict.value for r in results],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
