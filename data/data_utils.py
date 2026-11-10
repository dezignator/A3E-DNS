"""Shared helpers for the data pipeline.

Used by every script in ``data/`` and by the Dask preprocessing chain.
The module is deliberately small: it provides paths, hashing, and a
deterministic label/traffic generator, and nothing else.

Public API
----------
    DEFAULT_SEED
    DATA_ROOT
    PATHS
    sha256_file(path)               -> str
    sha256_bytes(data)              -> str
    write_manifest(paths, output)   -> None
    read_manifest(path)             -> dict
    deterministic_traffic(seed, n)  -> np.ndarray
    deterministic_labels(seed, n)   -> np.ndarray
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import numpy as np

__all__ = [
    "DEFAULT_SEED",
    "DATA_ROOT",
    "PATHS",
    "sha256_file",
    "sha256_bytes",
    "write_manifest",
    "read_manifest",
    "deterministic_traffic",
    "deterministic_labels",
]

#: Master seed (thesis submission date, 2026-11-30).
DEFAULT_SEED: int = 20261130

#: Root of the ``data/`` package.
DATA_ROOT: Path = Path(__file__).resolve().parent


@dataclass(frozen=True)
class _Paths:
    """Canonical paths inside ``data/``."""

    root: Path = DATA_ROOT
    raw: Path = field(default_factory=lambda: DATA_ROOT / "raw")
    zenodo: Path = field(default_factory=lambda: DATA_ROOT / "zenodo")
    doh_realworld: Path = field(default_factory=lambda: DATA_ROOT / "doh_realworld")
    kosekmi_doq: Path = field(default_factory=lambda: DATA_ROOT / "kosekmi_doq")
    processed: Path = field(default_factory=lambda: DATA_ROOT / "processed")
    synthetic: Path = field(default_factory=lambda: DATA_ROOT / "synthetic")
    threat_feeds: Path = field(default_factory=lambda: DATA_ROOT / "threat_feeds")
    manifest: Path = field(default_factory=lambda: DATA_ROOT / "MANIFEST.sha256")


PATHS = _Paths()


# ---------------------------------------------------------------- hashing
def sha256_file(path: str | Path, *, chunk_size: int = 1 << 20) -> str:
    """SHA-256 hex digest of a file, streaming in 1 MiB chunks."""
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of a bytes object."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- manifest
def write_manifest(paths: Iterable[str | Path], output: str | Path) -> None:
    """Write a ``sha256sum``-compatible manifest for the given files.

    Each line is ``<hex-digest>  <relative-path>`` (two spaces, matching
    the GNU ``sha256sum`` format).
    """
    output = Path(output)
    lines: list[str] = []
    for p in sorted(Path(x) for x in paths):
        digest = sha256_file(p)
        try:
            rel = p.relative_to(DATA_ROOT)
        except ValueError:
            rel = p
        lines.append(f"{digest}  {rel}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_manifest(path: str | Path) -> dict[str, str]:
    """Read a ``sha256sum``-style manifest into ``{relative_path: digest}``.

    Comment lines (starting with ``#``) are skipped.
    """
    path = Path(path)
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, rel = parts
        out[rel] = digest
    return out


# ---------------------------------------------------------------- deterministic data
def deterministic_traffic(
    seed: int = DEFAULT_SEED,
    *,
    n_samples: int = 1024,
    n_features: int = 128,
) -> np.ndarray:
    """Deterministic traffic feature matrix.

    Used as the toy-mode stand-in for the real 32 GB Zenodo dataset.
    The features are drawn from a mixture of benign-like and
    attack-like distributions so that a downstream detector has
    something to separate. The exact distributions are not claimed to
    match the real data.

    Returns
    -------
    np.ndarray, shape ``(n_samples, n_features)``
    """
    rng = np.random.default_rng(seed)
    n_benign = n_samples // 2
    n_attack = n_samples - n_benign
    benign = rng.normal(0.0, 1.0, size=(n_benign, n_features))
    attack = rng.normal(1.5, 1.2, size=(n_attack, n_features))
    X = np.vstack([benign, attack])
    # Shuffle so the labels are not clustered.
    perm = rng.permutation(n_samples)
    return X[perm]


def deterministic_labels(
    seed: int = DEFAULT_SEED,
    *,
    n_samples: int = 1024,
) -> np.ndarray:
    """Deterministic binary labels matching :func:`deterministic_traffic`.

    Returns ``1`` for the attack half, ``0`` for the benign half, then
    shuffles with the same permutation as the traffic generator so that
    the two line up.

    Returns
    -------
    np.ndarray, shape ``(n_samples,)``, dtype ``int64``
    """
    rng = np.random.default_rng(seed)
    n_benign = n_samples // 2
    n_attack = n_samples - n_benign
    labels = np.concatenate([np.zeros(n_benign, dtype=np.int64), np.ones(n_attack, dtype=np.int64)])
    perm = rng.permutation(n_samples)
    return labels[perm]


# ---------------------------------------------------------------- metadata
def metadata() -> dict:
    """Return the manifest metadata block."""
    return {
        "default_seed": DEFAULT_SEED,
        "data_root": str(DATA_ROOT),
        "synthetic_dir": str(PATHS.synthetic),
        "threat_feeds_dir": str(PATHS.threat_feeds),
    }


if __name__ == "__main__":  # pragma: no cover - convenience only
    print(json.dumps(metadata(), indent=2))
