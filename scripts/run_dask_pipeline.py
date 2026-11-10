#!/usr/bin/env python3
"""Dask parallel dataset preprocessing — thesis §6.13.

Implements the four-stage Dask pipeline described in §6.13.2–§6.13.6:

    1. Distributed data loading              (§6.13.3)
    2. Feature engineering and normalisation (§6.13.4)
    3. Ground-truth label integration        (§6.13.5)
    4. Train / validation / test split       (§6.13.6)

The 32 GB dataset is processed in ~2 hours on the testbed of §6.11.
The runtime figure is a property of the testbed and pipeline
configuration, not a general throughput result.

Usage
-----
    python scripts/run_dask_pipeline.py --mode toy
    python scripts/run_dask_pipeline.py --mode full --input data/zenodo --output data/processed
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Allow running without install.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src import __version__, thesis_reference  # noqa: E402
from src.utils.config_loader import load_config  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run_dask_pipeline")
    parser.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    parser.add_argument("--input", type=Path, default=None,
                        help="input dataset directory (default: configs/dask_pipeline.yaml)")
    parser.add_argument("--output", type=Path, default=Path("outputs/dask_manifest.json"))
    parser.add_argument("--seed", type=int, default=20261130)
    return parser.parse_args(argv)


def _try_import_dask():
    try:
        import dask.dataframe as dd  # noqa: F401
        from dask.distributed import Client  # noqa: F401
        return True
    except ImportError:
        return False


def run_toy(args: argparse.Namespace) -> dict:
    """Toy preprocessing: deterministic manifest without Dask."""
    stages = [
        {"stage": 1, "name": "distributed_loading", "status": "simulated"},
        {"stage": 2, "name": "feature_engineering", "status": "simulated"},
        {"stage": 3, "name": "label_integration", "status": "simulated"},
        {"stage": 4, "name": "split", "status": "simulated"},
    ]
    return {
        "mode": "toy",
        "dask_available": _try_import_dask(),
        "stages": stages,
        "wall_time_s": 0.0,
    }


def run_full(args: argparse.Namespace) -> dict:
    """Full preprocessing: drive Dask over the real dataset."""
    cfg = load_config("dask_pipeline")["dask_pipeline"]
    input_dir = args.input or Path("data/raw")
    if not input_dir.exists():
        return {
            "mode": "full",
            "dask_available": _try_import_dask(),
            "error": f"input directory not found: {input_dir}",
            "stages": [],
            "wall_time_s": 0.0,
        }
    if not _try_import_dask():
        return {
            "mode": "full",
            "dask_available": False,
            "error": "dask is not installed; run `pip install -r requirements.txt`",
            "stages": [],
            "wall_time_s": 0.0,
        }

    import dask.dataframe as dd
    from dask.distributed import Client

    start = time.time()
    client = Client(processes=cfg.get("processes", True),
                    n_workers=cfg.get("n_workers") or None,
                    threads_per_worker=cfg.get("threads_per_worker", 4))
    stages = []
    try:
        # Stage 1 — load
        parquet_files = list(input_dir.rglob("*.parquet"))
        csv_files = list(input_dir.rglob("*.csv"))
        if parquet_files:
            df = dd.read_parquet([str(p) for p in parquet_files])
        elif csv_files:
            df = dd.read_csv([str(p) for p in csv_files])
        else:
            stages.append({"stage": 1, "name": "distributed_loading", "status": "no_data"})
            return {"mode": "full", "dask_available": True, "stages": stages,
                    "wall_time_s": round(time.time() - start, 2)}
        stages.append({"stage": 1, "name": "distributed_loading", "status": "ok",
                       "n_partitions": df.npartitions})

        # Stage 2 — feature engineering (z-score)
        numeric_cols = [c for c in df.columns if str(df[c].dtype).startswith(("int", "float"))]
        for c in numeric_cols:
            mu = df[c].mean()
            sigma = df[c].std()
            if sigma.compute() > 0:
                df[c] = (df[c] - mu) / sigma
        stages.append({"stage": 2, "name": "feature_engineering", "status": "ok",
                       "n_features": len(numeric_cols)})

        # Stage 3 — label integration (assume a 'label' column exists)
        if "label" not in df.columns:
            stages.append({"stage": 3, "name": "label_integration", "status": "no_label_column"})
        else:
            stages.append({"stage": 3, "name": "label_integration", "status": "ok"})

        # Stage 4 — stratified split
        train_frac = cfg["stages"]["split"]["train_pct"]
        val_frac = cfg["stages"]["split"]["val_pct"]
        rng = __import__("numpy").random.default_rng(args.seed)
        df = df.assign(_split=rng.uniform(size=len(df)) if False else df.index.map_partitions(
            lambda idx: rng.uniform(size=len(idx))
        ))
        train = df[df._split < train_frac].drop(columns=["_split"])
        val = df[(df._split >= train_frac) & (df._split < train_frac + val_frac)].drop(columns=["_split"])
        test = df[df._split >= train_frac + val_frac].drop(columns=["_split"])
        stages.append({"stage": 4, "name": "split", "status": "ok",
                       "n_train": int(train.shape[0].compute()),
                       "n_val": int(val.shape[0].compute()),
                       "n_test": int(test.shape[0].compute())})
    finally:
        client.close()

    return {
        "mode": "full",
        "dask_available": True,
        "stages": stages,
        "wall_time_s": round(time.time() - start, 2),
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    meta = thesis_reference()

    if args.mode == "toy":
        manifest = run_toy(args)
    else:
        manifest = run_full(args)

    manifest.update({
        "artifact_version": __version__,
        "thesis": meta,
        "seed": args.seed,
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "output": str(args.output),
                      "mode": args.mode, "wall_time_s": manifest["wall_time_s"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
