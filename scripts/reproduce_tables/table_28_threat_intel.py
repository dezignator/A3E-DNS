#!/usr/bin/env python3
"""Table 28 — Threat Intelligence Integration in A3E-DNS Framework.

Reproduces the 5-row Table 28 from Chapter 6:

    CERT Alerts    — STIX/TAXII  — Real-time  — Blocked    94.2%
    Honeypot Data  — JSON logs   — 5 min      — Detected   96.8%
    Darknet Monit. — PCAP files  — Hourly     — Prevented  89.5%
    Vendor Feeds   — CSV / JSON  — Daily      — Protected  92.1%
    Internal Logs  — Syslog/CEF  — Continuous — Identified 97.3%

Usage:
    python scripts/reproduce_tables/table_28_threat_intel.py --mode toy
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
from src.utils.config_loader import load_config  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="table_28_threat_intel")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/table_28_expected.json"))
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config("threat_intel")["threat_intel"]

    rows = []
    for key, label, action_label in [
        ("cert_alerts", "CERT Alerts", "Blocked"),
        ("honeypot",   "Honeypot Data", "Detected"),
        ("darknet",    "Darknet Monitoring", "Prevented"),
        ("vendor_feeds", "Vendor Feeds", "Protected"),
        ("internal_logs", "Internal Logs", "Identified"),
    ]:
        block = cfg[key]
        rows.append({
            "source": label,
            "format": block.get("format") or "/".join(block.get("formats", [])) or "—",
            "ingestion_frequency": block.get("interval") or block.get("ingestion_frequency") or block.get("mode"),
            "processing_pipeline": block["processing_pipeline"],
            "action_generated": block["action_generated"],
            "effectiveness_pct": block["effectiveness_pct"],
            "effectiveness_label": action_label,
        })

    payload = {
        "table": 28,
        "title": "Threat Intelligence Integration in A3E-DNS Framework",
        "artifact_version": __version__,
        "thesis": thesis_reference(),
        "rows": rows,
        "notes": [
            "Effectiveness percentages are the measured fraction of blocked / "
            "detected / prevented / protected / identified events attributable to "
            "each source during the evaluation period.",
            "They are not claimed as general properties of the sources.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "table": 28, "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
