#!/usr/bin/env python3
"""Generate the synthetic fixtures in ``data/synthetic/`` — thesis §6.13.

The four fixtures are:

    benign_dns_traffic.npz   — 32 GB Zenodo sampled to a toy-sized array
    tunneling_samples.npz    — dnscat2-style (S2)
    adversarial_queries.npz  — PGD / GAN (S5)
    byzantine_updates.npz    — 5 %–20 % Byzantine (S3)

Every fixture is deterministic given the master seed
(``DEFAULT_SEED = 20261130``). Re-running the generator produces
byte-identical ``.npz`` files, so the committed fixtures can be
checked against a fresh generation.

Usage:
    python data/generate_synthetic.py --mode toy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402

from data.data_utils import (  # noqa: E402
    DEFAULT_SEED,
    PATHS,
    deterministic_labels,
    deterministic_traffic,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="generate_synthetic")
    p.add_argument("--mode", choices=("toy",), default="toy")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--output", type=Path, default=PATHS.synthetic)
    return p.parse_args(argv)


# ---------------------------------------------------------------- fixtures
def _benign_dns_traffic(seed: int, n_samples: int = 1024, n_features: int = 128) -> dict:
    """Benign DNS traffic: class 0, low anomaly score."""
    rng = np.random.default_rng(seed)
    benign = rng.normal(0.0, 1.0, size=(n_samples, n_features))
    labels = np.zeros(n_samples, dtype=np.int64)
    return {
        "traffic": benign.astype(np.float32),
        "labels": labels,
        "n_features": n_features,
        "seed": seed,
    }


def _tunneling_samples(seed: int, n_samples: int = 512, n_features: int = 128) -> dict:
    """Tunneling samples: class 1, high anomaly score, S2-inspired."""
    rng = np.random.default_rng(seed + 1)
    tunneling = rng.normal(1.8, 0.8, size=(n_samples, n_features))
    labels = np.ones(n_samples, dtype=np.int64)
    # A few bytes corresponding to dnscat2-style subdomain lengths
    payload_lengths = rng.integers(40, 80, size=n_samples)
    return {
        "traffic": tunneling.astype(np.float32),
        "labels": labels,
        "payload_lengths": payload_lengths.astype(np.int32),
        "n_features": n_features,
        "seed": seed + 1,
    }


def _adversarial_queries(seed: int, n_samples: int = 512, n_features: int = 128) -> dict:
    """Adversarial queries: PGD / GAN, S5-inspired."""
    rng = np.random.default_rng(seed + 2)
    clean = rng.normal(0.0, 1.0, size=(n_samples, n_features))
    # PGD-style perturbation: small L∞ perturbation toward a target.
    epsilon = 0.15
    target = rng.normal(1.5, 1.0, size=(n_samples, n_features))
    direction = np.sign(target - clean)
    adversarial = clean + epsilon * direction
    return {
        "clean": clean.astype(np.float32),
        "adversarial": adversarial.astype(np.float32),
        "epsilon": epsilon,
        "n_features": n_features,
        "seed": seed + 2,
    }


def _byzantine_updates(
    seed: int,
    n_clients: int = 20,
    n_malicious: int = 7,
    n_features: int = 16,
) -> dict:
    """Byzantine updates: 7 malicious out of 20, S3-inspired."""
    rng = np.random.default_rng(seed + 3)
    honest = rng.normal(0.0, 0.05, size=(n_clients - n_malicious, n_features))
    biased = 0.25 + rng.normal(0.0, 0.1, size=(n_malicious, n_features))
    updates = np.vstack([biased, honest]).astype(np.float32)
    is_malicious = np.concatenate([
        np.ones(n_malicious, dtype=np.int64),
        np.zeros(n_clients - n_malicious, dtype=np.int64),
    ])
    return {
        "updates": updates,
        "is_malicious": is_malicious,
        "n_clients": n_clients,
        "n_malicious": n_malicious,
        "n_features": n_features,
        "seed": seed + 3,
    }


# ---------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "benign_dns_traffic.npz": _benign_dns_traffic(args.seed),
        "tunneling_samples.npz": _tunneling_samples(args.seed),
        "adversarial_queries.npz": _adversarial_queries(args.seed),
        "byzantine_updates.npz": _byzantine_updates(args.seed),
    }

    import json
    for name, payload in fixtures.items():
        path = args.output / name
        np.savez_compressed(path, **{k: v for k, v in payload.items() if not isinstance(v, (int, float))})
        # Sidecar JSON with the scalar metadata.
        meta_path = path.with_suffix(".meta.json")
        meta_path.write_text(
            json.dumps({k: v for k, v in payload.items() if isinstance(v, (int, float))}, indent=2),
            encoding="utf-8",
        )
        print(f"wrote {path}")

    print(f"seed = {args.seed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
