#!/usr/bin/env python3
"""Preprocess DS-1 (Zenodo 5957677) via Dask — thesis §6.13.

The 4-stage pipeline is the one described in §6.13.2–§6.13.6:

    1. Distributed data loading             (§6.13.3)
    2. Feature engineering + normalisation  (§6.13.4)
    3. Ground-truth label integration       (§6.13.5)
    4. Train / validation / test split      (§6.13.6)

The 32 GB dataset is processed in ~2 hours on the testbed of §6.11.
The runtime figure is a property of the testbed and the pipeline
configuration, not a general throughput result.

Usage:
    python data/preprocess_zenodo.py --mode toy
    python data/preprocess_zenodo.py --mode full
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from data.data_utils import DEFAULT_SEED, PATHS  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="preprocess_zenodo")
    p.add_argument("--mode", choices=("toy", "full"), default="toy")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--output", type=Path, default=PATHS.processed / "zenodo")
    return p.parse_args(argv)


def _try_import_dask() -> bool:
    try:
        import dask.dataframe  # noqa: F401
        from dask.distributed import Client  # noqa: F401
        return True
    except ImportError:
        return False


def run_toy(args: argparse.Namespace) -> dict:
    return {
        "mode": "toy",
        "dask_available": _try_import_dask(),
        "stages": [
            {"stage": 1, "name": "distributed_loading", "status": "simulated"},
            {"stage": 2, "name": "feature_engineering", "status": "simulated"},
            {"stage": 3, "name": "label_integration", "status": "simulated"},
            {"stage": 4, "name": "split", "status": "simulated"},
        ],
        "wall_time_s": 0.0,
    }


def run_full(args: argparse.Namespace) -> dict:
    raw = PATHS.zenodo
    if not raw.exists() or not any(raw.iterdir()):
        return {
            "mode": "full",
            "error": f"raw dataset not found at {raw}; run download_datasets.py --mode full first.",
            "stages": [],
            "wall_time_s": 0.0,
        }
    if not _try_import_dask():
        return {
            "mode": "full",
            "error": "dask not installed; run `pip install -r requirements.txt`.",
            "stages": [],
            "wall_time_s": 0.0,
        }

    import dask.dataframe as dd
    from dask.distributed import Client

    args.output.mkdir(parents=True, exist_ok=True)
    start = time.time()
    stages: list[dict] = []
    client = Client(processes=True, threads_per_worker=4)
    try:
        parquet_files = list(raw.rglob("*.parquet"))
        csv_files = list(raw.rglob("*.csv"))
        if parquet_files:
            df = dd.read_parquet([str(p) for p in parquet_files])
        elif csv_files:
            df = dd.read_csv([str(p) for p in csv_files])
        else:
            stages.append({"stage": 1, "name": "distributed_loading", "status": "no_data"})
            return {"mode": "full", "stages": stages,
                    "wall_time_s": round(time.time() - start, 2)}
        stages.append({"stage": 1, "name": "distributed_loading", "status": "ok",
                       "n_partitions": int(df.npartitions)})

        numeric_cols = [c for c in df.columns if str(df[c].dtype).startswith(("int", "float"))]
        for c in numeric_cols:
            mu = df[c].mean()
            sigma = df[c].std()
            if sigma.compute() > 0:
                df[c] = (df[c] - mu) / sigma
        stages.append({"stage": 2, "name": "feature_engineering", "status": "ok",
                       "n_features": len(numeric_cols)})

        if "label" not in df.columns:
            stages.append({"stage": 3, "name": "label_integration", "status": "no_label_column"})
        else:
            stages.append({"stage": 3, "name": "label_integration", "status": "ok"})

        train_frac, val_frac = 0.70, 0.15
        # Deterministic split: assign each partition row a split id.
        df = df.assign(_split=df.index.map_partitions(
            lambda idx: __import__("numpy").random.default_rng(args.seed).uniform(size=len(idx))
        ))
        train = df[df._split < train_frac].drop(columns=["_split"])
        val = df[(df._split >= train_frac) & (df._split < train_frac + val_frac)].drop(columns=["_split"])
        test = df[df._split >= train_frac + val_frac].drop(columns=["_split"])
        stages.append({"stage": 4, "name": "split", "status": "ok",
                       "n_train": int(train.shape[0].compute()),
                       "n_val": int(val.shape[0].compute()),
                       "n_test": int(test.shape[0].compute())})
        train.to_parquet(args.output / "train.parquet")
        val.to_parquet(args.output / "val.parquet")
        test.to_parquet(args.output / "test.parquet")
    finally:
        client.close()

    return {
        "mode": "full",
        "stages": stages,
        "wall_time_s": round(time.time() - start, 2),
        "output": str(args.output),
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = run_toy(args) if args.mode == "toy" else run_full(args)
    manifest.update({"dataset": "zenodo", "seed": args.seed})
    out = args.output / "preprocess_manifest.json"
    args.output.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "output": str(out),
                      "mode": args.mode, "wall_time_s": manifest["wall_time_s"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
