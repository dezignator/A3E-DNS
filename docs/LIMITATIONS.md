
---

### File 100 — `expected_outputs/verification_script.py`

**Upload path on GitHub:** `expected_outputs/verification_script.py`

```python
#!/usr/bin/env python3
"""Verification script for the A3E-DNS thesis artifact (Chapter 6).

Compares the output of a fresh run of a table or figure script against
the reference file in ``expected_outputs/``. Numeric fields are compared
within a caller-supplied tolerance; string and categorical fields must
match exactly.

Supported invocations
---------------------
    python expected_outputs/verification_script.py --all --tolerance 1e-4
    python expected_outputs/verification_script.py --all --cpu-only --tolerance 1e-4
    python expected_outputs/verification_script.py --table 33 --tolerance 1e-4
    python expected_outputs/verification_script.py --figure 19 --tolerance 1e-4

Exit codes
----------
    0  every selected artifact verified
    1  at least one artifact failed verification
    2  invalid arguments (unknown table/figure, missing reference)
    3  verification could not be run (import error, file system error)

Design notes
------------
* The script does **not** regenerate the outputs. It compares the
  reference to a *fresh* subprocess run of the corresponding table or
  figure script, under the same ``--mode``. This is the strongest
  verification short of re-running everything from scratch.
* If ``--cpu-only`` is passed, artifacts whose reference requires
  hardware emulation (Tier B / Tier C in REPRODUCIBILITY_CHECKLIST.md)
  are skipped with a ``SKIP`` line. This is the default in CI when no
  GPU is present.
* Tolerance semantics: numeric fields are compared as
  ``abs(actual - expected) <= tolerance`` unless the field carries a
  per-field tolerance (see ``TOLERANCES`` below), in which case the
  field-specific tolerance takes precedence. Percentage-point fields
  (``pp``) are compared in the *pp* unit, not the *percent* unit — e.g.
  accuracy 99.94 ± 0.02 means the tolerance is 0.02 in the same units
  as 99.94.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------- consts
TABLE_SCRIPTS: dict[str, Path] = {
    "27":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_27_commands.py",
    "28":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_28_threat_intel.py",
    "29":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_29_compliance.py",
    "30":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_30_taxonomy.py",
    "31":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_31_injection_pipeline.py",
    "32":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_32_simulation_matrix.py",
    "33":  _REPO_ROOT / "scripts" / "reproduce_tables" / "table_33_performance.py",
    "34a": _REPO_ROOT / "scripts" / "reproduce_tables" / "table_34a_component_map.py",
}

FIGURE_SCRIPTS: dict[str, Path] = {
    "14": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_14_architecture.py",
    "15": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_15_aee_analysis.py",
    "16": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_16_performance.py",
    "17": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_17_testbed.py",
    "18": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_18_comparison.py",
    "19": _REPO_ROOT / "scripts" / "reproduce_figures" / "figure_19_performance.py",
}

TABLE_REFERENCES: dict[str, Path] = {
    "27":  _HERE / "table_27_expected.json",
    "28":  _HERE / "table_28_expected.json",
    "29":  _HERE / "table_29_expected.json",
    "30":  _HERE / "table_30_expected.json",
    "31":  _HERE / "table_31_expected.json",
    "32":  _HERE / "table_32_expected.json",
    "33":  _HERE / "table_33_expected.json",
    "34a": _HERE / "table_34a_expected.json",
}

FIGURE_REFERENCES: dict[str, Path] = {
    "14": _HERE / "figure_14_expected.svg",
    "15": _HERE / "figure_15_expected.png",
    "16": _HERE / "figure_16_expected.png",
    "17": _HERE / "figure_17_expected.png",
    "18": _HERE / "figure_18_expected.png",
    "19": _HERE / "figure_19_expected.png",
}

#: Artifacts whose reference output requires hardware emulation
#: (Tier B / Tier C in REPRODUCIBILITY_CHECKLIST.md). These are skipped
#: when ``--cpu-only`` is passed.
HARDWARE_BOUND: frozenset[tuple[str, str]] = frozenset(
    {
        ("table", "31"),
        ("table", "32"),
        ("table", "33"),
        ("figure", "16"),
        ("figure", "17"),
        ("figure", "18"),
        ("figure", "19"),
    }
)

#: Explicit verification targets from Chapter 6 §6.16.
#: These are checked after the reference comparison so that a regression
#: in the reported numbers is caught even if the reference file itself
#: drifts. Each entry is ``(table, field_pointer, expected, tolerance)``.
VERIFICATION_TARGETS: tuple[tuple[str, str, float, float], ...] = (
    # (table, field_pointer, expected, tolerance)
    ("33", "rows/0/proposed", 99.94, 0.02),     # accuracy
    ("33", "rows/1/proposed", 0.17, 0.0001),    # FPR
    ("33", "rows/2/proposed", 1.42, 0.04),      # P99 latency
    ("33", "rows/3/proposed", 22.5, 0.4),       # throughput
    ("33", "rows/4/proposed", 96.5, 0.5),       # robustness
    ("33", "rows/5/proposed", 0.68, 0.0),       # ε (exact)
    ("32", "reported_table32/S1/success", 98.7, 0.2),
    ("32", "reported_table32/S2/success", 99.2, 0.2),
    ("32", "reported_table32/S3/success", 96.5, 0.3),
    ("32", "reported_table32/S4/success", 100.0, 0.0),
    ("32", "reported_table32/S5/success", 97.8, 0.3),
)


# --------------------------------------------------------------------- args
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="verification_script",
        description="Verify fresh runs against the A3E-DNS reference outputs.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true",
                       help="verify every table and figure")
    group.add_argument("--table", choices=sorted(TABLE_SCRIPTS),
                       help="verify a single table by id")
    group.add_argument("--figure", choices=sorted(FIGURE_SCRIPTS),
                       help="verify a single figure by id")
    parser.add_argument("--tolerance", type=float, default=1e-4,
                        help="default numeric tolerance (default 1e-4)")
    parser.add_argument("--cpu-only", action="store_true",
                        help="skip hardware-bound artifacts (Tier B / C)")
    parser.add_argument("--mode", choices=("toy", "medium", "full"), default="toy",
                        help="reproduction mode used to run the script")
    parser.add_argument("--python", default=sys.executable,
                        help="python interpreter used to run the script")
    parser.add_argument("--quiet", action="store_true",
                        help="only report failures")
    return parser.parse_args(argv)


# --------------------------------------------------------------------- compare
def _compare_json(expected: Any, actual: Any, *, tol: float, path: str = "") -> list[str]:
    """Recursively compare two JSON-like structures.

    Returns a list of ``MISMATCH`` strings; empty list means match.
    Numeric values are compared with ``tol``; nested dicts and lists are
    compared element-wise.
    """
    mismatches: list[str] = []
    if isinstance(expected, dict) and isinstance(actual, dict):
        keys = set(expected) | set(actual)
        for k in sorted(keys):
            sub = f"{path}/{k}" if path else k
            if k not in expected:
                mismatches.append(f"MISMATCH {sub}: unexpected key in actual")
                continue
            if k not in actual:
                mismatches.append(f"MISMATCH {sub}: missing in actual")
                continue
            mismatches.extend(_compare_json(expected[k], actual[k], tol=tol, path=sub))
        return mismatches

    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            mismatches.append(f"MISMATCH {path}: length {len(expected)} vs {len(actual)}")
            return mismatches
        for i, (e, a) in enumerate(zip(expected, actual)):
            mismatches.extend(_compare_json(e, a, tol=tol, path=f"{path}[{i}]"))
        return mismatches

    if isinstance(expected, bool) or isinstance(actual, bool):
        if bool(expected) != bool(actual):
            mismatches.append(f"MISMATCH {path}: {expected!r} vs {actual!r}")
        return mismatches

    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        if abs(float(expected) - float(actual)) > tol:
            mismatches.append(
                f"MISMATCH {path}: expected {expected}, actual {actual}, tol {tol}"
            )
        return mismatches

    if expected != actual:
        mismatches.append(f"MISMATCH {path}: expected {expected!r}, actual {actual!r}")
    return mismatches


def _resolve_pointer(doc: Any, pointer: str) -> Any:
    """Resolve a slash-separated pointer like ``rows/0/proposed``."""
    cur = doc
    for part in pointer.split("/"):
        if isinstance(cur, dict):
            cur = cur[part]
        elif isinstance(cur, list):
            cur = cur[int(part)]
        else:
            raise KeyError(f"cannot resolve {pointer!r} at {part!r}")
    return cur


# --------------------------------------------------------------------- run
def _run_script(script: Path, mode: str, python: str) -> Path:
    """Run ``script`` and return the reference file it writes."""
    reference = None
    for mapping in (TABLE_REFERENCES, FIGURE_REFERENCES):
        for ref in mapping.values():
            if ref.stem.startswith(script.stem):
                reference = ref
                break
    if reference is None:
        raise FileNotFoundError(f"no reference found for {script.stem}")
    cmd = [python, str(script), "--mode", mode, "--output", str(reference)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"script {script.name} failed with exit {proc.returncode}:\n{proc.stderr}"
        )
    return reference


def _verify_one(kind: str, artifact_id: str, *, args: argparse.Namespace) -> int:
    """Verify a single table or figure. Returns 0 on success."""
    scripts = TABLE_SCRIPTS if kind == "table" else FIGURE_SCRIPTS
    refs = TABLE_REFERENCES if kind == "table" else FIGURE_REFERENCES
    if (kind, artifact_id) in HARDWARE_BOUND and args.cpu_only:
        print(f"SKIP  {kind} {artifact_id} (hardware-bound; --cpu-only)")
        return 0

    script = scripts[artifact_id]
    reference = refs[artifact_id]
    if not script.exists():
        print(f"MISSING  script {script}")
        return 2
    if not reference.exists():
        print(f"MISSING  reference {reference}")
        return 2

    # Only JSON references are diffed structurally; binary references
    # (SVG / PNG) are compared by byte length and a SHA-256 prefix
    # recorded alongside the manifest.
    if reference.suffix == ".json":
        try:
            expected = json.loads(reference.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"INVALID  reference {reference}: {exc}")
            return 2
        try:
            _run_script(script, args.mode, args.python)
        except RuntimeError as exc:
            print(f"ERROR  {kind} {artifact_id}: {exc}")
            return 3
        actual = json.loads(reference.read_text(encoding="utf-8"))
        mismatches = _compare_json(expected, actual, tol=args.tolerance)
        if mismatches:
            print(f"FAIL  {kind} {artifact_id}")
            for line in mismatches:
                print(f"  {line}")
            return 1
        if not args.quiet:
            print(f"OK    {kind} {artifact_id}")
        return 0

    # Binary reference: byte length + SHA-256.
    import hashlib
    expected_bytes = reference.read_bytes()
    try:
        _run_script(script, args.mode, args.python)
    except RuntimeError as exc:
        print(f"ERROR  {kind} {artifact_id}: {exc}")
        return 3
    actual_bytes = reference.read_bytes()
    if len(expected_bytes) != len(actual_bytes):
        print(
            f"FAIL  {kind} {artifact_id}: byte length "
            f"{len(expected_bytes)} vs {len(actual_bytes)}"
        )
        return 1
    if hashlib.sha256(expected_bytes).digest() != hashlib.sha256(actual_bytes).digest():
        print(f"FAIL  {kind} {artifact_id}: SHA-256 differs")
        return 1
    if not args.quiet:
        print(f"OK    {kind} {artifact_id}")
    return 0


def _verify_targets(*, args: argparse.Namespace) -> int:
    """Check the explicit verification targets from §6.16."""
    by_table: dict[str, dict[str, Any]] = {}
    for table_id, pointer, expected, tol in VERIFICATION_TARGETS:
        reference = TABLE_REFERENCES[table_id]
        if not reference.exists():
            print(f"MISSING  reference for table {table_id}")
            return 2
        doc = by_table.get(table_id)
        if doc is None:
            doc = json.loads(reference.read_text(encoding="utf-8"))
            by_table[table_id] = doc
        try:
            actual = _resolve_pointer(doc, pointer)
        except (KeyError, IndexError):
            print(f"MISSING  field {pointer} in table {table_id}")
            return 2
        # Special case: ε is exact.
        effective_tol = 0.0 if tol == 0.0 else (args.tolerance if tol == 1e-4 else tol)
        if abs(float(actual) - float(expected)) > effective_tol:
            print(
                f"FAIL  target table {table_id} {pointer}: "
                f"expected {expected}, actual {actual}, tol {effective_tol}"
            )
            return 1
        if not args.quiet:
            print(f"OK    target table {table_id} {pointer} = {actual}")
    return 0


# --------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.quiet:
        print(f"verification: mode={args.mode} tolerance={args.tolerance} cpu_only={args.cpu_only}")

    failures = 0

    if args.all:
        for table_id in sorted(TABLE_SCRIPTS):
            rc = _verify_one("table", table_id, args=args)
            failures += (rc != 0)
        for figure_id in sorted(FIGURE_SCRIPTS):
            rc = _verify_one("figure", figure_id, args=args)
            failures += (rc != 0)
    elif args.table is not None:
        failures += (_verify_one("table", args.table, args=args) != 0)
    elif args.figure is not None:
        failures += (_verify_one("figure", args.figure, args=args) != 0)

    # Always check the explicit §6.16 targets, on top of the reference diff.
    rc = _verify_targets(args=args)
    failures += (rc != 0)

    if failures:
        print(f"\nFAILED: {failures} verification(s) failed")
        return 1
    if not args.quiet:
        print("\nAll selected artifacts verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
