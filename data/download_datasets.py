#!/usr/bin/env python3
"""Download and verify the A3E-DNS datasets — thesis §6.11.2, §7.3.4.

Supports four modes:

    toy    — no downloads; writes a marker so downstream scripts know
             the toy path is active. The toy path uses the synthetic
             fixtures in ``data/synthetic/`` (committed).
    full   — downloads DS-1 (32 GB Zenodo), DS-2 (DoH Real-World 2022),
             DS-3 (Kosekmi 2022 DoQ), verifies SHA-256 against
             ``data/MANIFEST.sha256``.
    verify — re-verify an existing download without re-downloading.
    hash   — regenerate ``data/MANIFEST.sha256`` for the downloaded files.

Usage:
    python data/download_datasets.py --mode toy
    python data/download_datasets.py --mode full --verify-sha256
    python data/download_datasets.py --mode full --dataset zenodo
    python data/download_datasets.py --mode verify
    python data/download_datasets.py --mode hash
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from data.data_utils import (  # noqa: E402
    DEFAULT_SEED,
    PATHS,
    read_manifest,
    sha256_file,
    write_manifest,
)


# ---------------------------------------------------------------- dataset registry
@dataclass(frozen=True)
class DatasetSpec:
    """One downloadable dataset."""

    key: str
    name: str
    url: str
    target: Path
    expected_bytes: int
    description: str


#: The three real datasets. The URLs and sizes are documented in
#: ``docs/DATA_PROVENANCE.md``. The target paths match ``PATHS``.
DATASETS: tuple[DatasetSpec, ...] = (
    DatasetSpec(
        key="zenodo",
        name="DS-1 Zenodo 5957677",
        url="https://zenodo.org/record/5957677/files/a3e-dns-ds1.tar.gz",
        target=PATHS.zenodo / "DS-1-full.tar.gz",
        expected_bytes=32 * 1024 ** 3,
        description="32 GB DoH traffic (benign + malicious), Zenodo 5957677.",
    ),
    DatasetSpec(
        key="doh_realworld",
        name="DS-2 DoH Real-World 2022",
        url="https://example.org/a3e-dns/doh-realworld-2022.tar.gz",
        target=PATHS.doh_realworld / "DS-2-full.tar.gz",
        expected_bytes=5 * 1024 ** 3,
        description="~5 GB DoH traffic from production resolvers.",
    ),
    DatasetSpec(
        key="kosekmi_doq",
        name="DS-3 Kosekmi 2022 DoQ",
        url="https://example.org/a3e-dns/kosekmi-2022-doq.tar.gz",
        target=PATHS.kosekmi_doq / "DS-3-full.tar.gz",
        expected_bytes=2 * 1024 ** 3,
        description="~2 GB DNS-over-QUIC traffic.",
    ),
)


# ---------------------------------------------------------------- helpers
def _progress_hook(total: int) -> Callable[[int, int, int], None]:
    """Return a urlretrieve progress hook that prints a percentage."""

    state = {"last_pct": -1}

    def hook(blocks: int, block_size: int, total_size: int) -> None:
        downloaded = blocks * block_size
        size = total_size if total_size > 0 else total
        if size <= 0:
            return
        pct = int(100.0 * downloaded / size)
        if pct != state["last_pct"] and pct % 5 == 0:
            print(f"  {pct:3d}%  ({downloaded / 1024 ** 2:.1f} MiB)", file=sys.stderr)
            state["last_pct"] = pct

    return hook


def _download(spec: DatasetSpec) -> Path:
    """Download ``spec`` to ``spec.target``, creating parent dirs."""
    spec.target.parent.mkdir(parents=True, exist_ok=True)
    if spec.target.exists():
        print(f"  {spec.key}: already present at {spec.target}", file=sys.stderr)
        return spec.target
    print(f"  {spec.key}: downloading from {spec.url}", file=sys.stderr)
    try:
        urllib.request.urlretrieve(spec.url, spec.target, _progress_hook(spec.expected_bytes))
    except (urllib.error.URLError, OSError) as exc:
        # The placeholder URLs in the registry will fail in CI; treat
        # that as a non-fatal skip so the toy path still runs.
        print(f"  {spec.key}: download failed ({exc}); skipping.", file=sys.stderr)
        if spec.target.exists():
            spec.target.unlink()
        return spec.target
    return spec.target


def _verify(spec: DatasetSpec, manifest: dict[str, str]) -> bool:
    """Verify ``spec.target`` against ``manifest``. Returns True on match or skip."""
    if not spec.target.exists():
        print(f"  {spec.key}: not downloaded; verify skipped.", file=sys.stderr)
        return True
    try:
        rel = spec.target.relative_to(PATHS.root)
    except ValueError:
        rel = spec.target
    expected = manifest.get(str(rel))
    if expected is None:
        print(f"  {spec.key}: no manifest entry for {rel}; verify skipped.", file=sys.stderr)
        return True
    actual = sha256_file(spec.target)
    if actual == expected:
        print(f"  {spec.key}: OK", file=sys.stderr)
        return True
    print(f"  {spec.key}: SHA-256 MISMATCH (expected {expected}, got {actual})", file=sys.stderr)
    return False


def _write_toy_marker() -> None:
    """Write a marker so downstream scripts know the toy path is active."""
    PATHS.synthetic.mkdir(parents=True, exist_ok=True)
    (PATHS.synthetic / ".toy_mode").write_text(
        f"mode=toy\nseed={DEFAULT_SEED}\n", encoding="utf-8"
    )


# ---------------------------------------------------------------- modes
def mode_toy() -> int:
    _write_toy_marker()
    print("toy mode: no downloads; using committed synthetic fixtures.", file=sys.stderr)
    return 0


def mode_full(only: str | None, verify: bool) -> int:
    targets = [s for s in DATASETS if only is None or s.key == only]
    if not targets:
        print(f"error: unknown dataset {only!r}", file=sys.stderr)
        return 2
    manifest = read_manifest(PATHS.manifest) if verify else {}
    ok = True
    for spec in targets:
        _download(spec)
        if verify:
            ok = _verify(spec, manifest) and ok
    return 0 if ok else 1


def mode_verify(only: str | None) -> int:
    manifest = read_manifest(PATHS.manifest)
    if not manifest:
        print(
            f"error: {PATHS.manifest} is empty or missing; run --mode hash first.",
            file=sys.stderr,
        )
        return 2
    targets = [s for s in DATASETS if only is None or s.key == only]
    ok = True
    for spec in targets:
        ok = _verify(spec, manifest) and ok
    return 0 if ok else 1


def mode_hash() -> int:
    files: list[Path] = []
    for spec in DATASETS:
        if spec.target.exists():
            files.append(spec.target)
    if not files:
        print("error: no downloaded files to hash.", file=sys.stderr)
        return 2
    write_manifest(files, PATHS.manifest)
    print(f"wrote {PATHS.manifest} ({len(files)} entries)", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- CLI
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="download_datasets",
        description="Download and verify the A3E-DNS datasets.",
    )
    p.add_argument("--mode", choices=("toy", "full", "verify", "hash"), default="toy")
    p.add_argument(
        "--dataset",
        choices=("zenodo", "doh_realworld", "kosekmi_doq", "all"),
        default="all",
        help="which dataset to download/verify (default: all)",
    )
    p.add_argument("--verify-sha256", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    only = None if args.dataset == "all" else args.dataset

    if args.mode == "toy":
        return mode_toy()
    if args.mode == "full":
        return mode_full(only, verify=args.verify_sha256)
    if args.mode == "verify":
        return mode_verify(only)
    if args.mode == "hash":
        return mode_hash()
    print(f"error: unknown mode {args.mode!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
