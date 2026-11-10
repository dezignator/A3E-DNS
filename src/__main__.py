"""Command-line entry point for the A3E-DNS package.

Usage:
    python -m src --help
    python -m src --mode toy --verify
    python -m src --mode medium --role fl-coordinator
    python -m src --mode full   --role qhe-service
    python -m src --mode toy    --device cpu

Role-based execution imports the corresponding module from
``src.models``, ``src.intel`` or ``src.dataplane`` and calls its
``run(...)`` function. Imports are deferred so that a partial checkout
(e.g. before all modules are present) still lets ``--help`` and
``--verify`` work.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import subprocess
import sys
from pathlib import Path

from src import __version__, thesis_reference


# ---------------------------------------------------------------- constants
VALID_MODES = ("toy", "medium", "full")
VALID_DEVICES = ("cpu", "cuda", "auto")

ROLE_TO_MODULE = {
    # FL coordinator
    "fl-coordinator":       "src.models.fl_coordinator",
    # QHE service
    "qhe-service":          "src.models.qhe_engine",
    # Anomaly detector + sandbox
    "anomaly-sandbox":      "src.models.anomaly_detector",
    # Threat intel + P4/eBPF data plane
    "threat-intel-dataplane": "src.intel.stix_parser",
}

VERIFICATION_SCRIPT = Path("expected_outputs") / "verification_script.py"


# ---------------------------------------------------------------- helpers
def _configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _print_banner() -> None:
    meta = thesis_reference()
    print(f"A3E-DNS {__version__} — {meta['chapter']} artifact", file=sys.stderr)


def _run_verify(tolerance: float, cpu_only: bool) -> int:
    """Run the expected_outputs verification script via subprocess."""
    if not VERIFICATION_SCRIPT.exists():
        print(
            f"[verify] {VERIFICATION_SCRIPT} is not present in this checkout. "
            "Skipping verification (this is expected before the first full commit).",
            file=sys.stderr,
        )
        return 0
    cmd = [
        sys.executable,
        str(VERIFICATION_SCRIPT),
        "--all",
        "--tolerance",
        str(tolerance),
    ]
    if cpu_only:
        cmd.append("--cpu-only")
    print(f"[verify] running: {' '.join(cmd)}", file=sys.stderr)
    return subprocess.call(cmd)


def _run_role(role: str, mode: str, device: str) -> int:
    """Dispatch to the module that owns the requested role."""
    module_name = ROLE_TO_MODULE.get(role)
    if module_name is None:
        print(
            f"[role] unknown role '{role}'. Known roles: "
            f"{sorted(ROLE_TO_MODULE)}",
            file=sys.stderr,
        )
        return 2
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        print(
            f"[role] '{role}' requires {module_name}, which is not yet "
            f"available in this checkout: {exc}",
            file=sys.stderr,
        )
        return 3
    run = getattr(module, "run", None)
    if run is None or not callable(run):
        print(
            f"[role] {module_name} does not expose a callable run(...); "
            f"cannot dispatch role '{role}'.",
            file=sys.stderr,
        )
        return 4
    return int(run(mode=mode, device=device) or 0)


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="a3e-dns",
        description=(
            "A3E-DNS thesis artifact (Chapter 6). "
            "Reproduce tables/figures, run a role service, or verify."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=VALID_MODES,
        default="toy",
        help="reproduction tier: toy (Tier A), medium (Tier B), full (Tiers A+B+D)",
    )
    parser.add_argument(
        "--device",
        choices=VALID_DEVICES,
        default="auto",
        help="compute device: cpu, cuda, or auto",
    )
    parser.add_argument(
        "--role",
        default=None,
        help=(
            "service role to run; one of "
            f"{sorted(ROLE_TO_MODULE)}"
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="run expected_outputs/verification_script.py after the main action",
    )
    parser.add_argument(
        "--cpu-only",
        action="store_true",
        help="with --verify: restrict to the CPU-reproducible artifacts (Tier A)",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=1e-4,
        help="verification tolerance (default: 1e-4)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging verbosity",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"a3e-dns {__version__}",
    )
    return parser


# ---------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)
    _print_banner()

    rc = 0

    # Role dispatch is optional; `--mode toy --verify` alone is valid.
    if args.role is not None:
        rc = _run_role(args.role, args.mode, args.device)
        if rc != 0:
            return rc

    if args.verify:
        verify_rc = _run_verify(args.tolerance, args.cpu_only)
        if verify_rc != 0:
            return verify_rc

    if args.role is None and not args.verify:
        print(
            "Nothing to do. Pass --role <name>, --verify, or both. "
            "Use --help for details.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
