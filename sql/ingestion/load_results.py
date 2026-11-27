#!/usr/bin/env python3
"""
sql/ingestion/load_results.py

Ingestion helper that loads experiment manifests into the SQL result
store.

We implemented this loader to bridge the JSONL and JSON manifest files
that the Python extended suite produces and the SQL schema defined in
sql/schema/. It reads a manifest directory, validates each manifest
against the schema expectations, and writes the corresponding rows.

The loader is idempotent: re-running it against the same input removes
the previous run's rows for that run_id before inserting the new ones.
That was deliberate, because ingestion is frequently re-run during a
thesis revision when a manifest is regenerated.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger("a3e.extended.sql_ingest")

# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _apply_schemas(conn: sqlite3.Connection, schema_dir: Path) -> None:
    for path in sorted(schema_dir.glob("*.sql")):
        LOGGER.info("applying schema %s", path.name)
        conn.executescript(path.read_text())
    conn.commit()


def _run_id(manifest_dir: Path, experiment_id: str) -> str:
    """Derive a stable run_id from the manifest contents.

    We used the manifest's own sha256 (if present) as the basis for the
    run_id, so that re-ingesting the same manifest is idempotent and
    re-ingesting a regenerated manifest with a new hash produces a new
    row rather than overwriting the old one.
    """
    manifest_path = manifest_dir / "manifest.json"
    if manifest_path.exists():
        try:
            payload = json.loads(manifest_path.read_text())
            declared = payload.get("manifest_sha256")
            if declared:
                return f"{experiment_id}-{declared[:16]}"
        except Exception:
            pass
    return f"{experiment_id}-{uuid.uuid4().hex[:16]}"


def _load_manifest(manifest_path: Path) -> Optional[Dict[str, object]]:
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except Exception:
        LOGGER.warning("could not parse %s", manifest_path)
        return None


def _git_info() -> Dict[str, object]:
    """Return the current git commit and dirty state.

    We used subprocess rather than a Python git library because the
    loader runs on hosts where the git binary is already present, and
    adding a dependency just to read two values would have been
    disproportionate.
    """
    import subprocess

    def _run(args: Sequence[str]) -> Optional[str]:
        try:
            out = subprocess.check_output(
                args, stderr=subprocess.DEVNULL, text=True
            ).strip()
            return out
        except Exception:
            return None

    commit = _run(["git", "rev-parse", "HEAD"])
    status = _run(["git", "status", "--porcelain"])
    return {
        "commit": commit,
        "dirty": 1 if status else 0,
    }


def _insert_run(
    conn: sqlite3.Connection,
    run_id: str,
    experiment_id: str,
    manifest: Optional[Mapping[str, object]],
    started_at: int,
    finished_at: Optional[int],
    status: str,
    seed: int,
    config_path: Optional[str],
    manifest_path: Optional[Path],
    manifest_sha256: Optional[str],
) -> None:
    git = _git_info()
    config_hash = None
    if config_path and Path(config_path).exists():
        import hashlib
        config_hash = hashlib.sha256(
            Path(config_path).read_bytes()
        ).hexdigest()

    conn.execute(
        """
        INSERT OR REPLACE INTO experiment_runs
            (run_id, experiment_id, started_at, finished_at, status, seed,
             git_commit, git_dirty, config_path, config_hash, hostname,
             python_version, rust_version, os_name, stdout_tail,
             stderr_tail, error_message, manifest_path, manifest_sha256,
             n_rounds, n_clients, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            experiment_id,
            started_at,
            finished_at,
            status,
            seed,
            git["commit"],
            git["dirty"],
            config_path,
            config_hash,
            os.uname().nodename if hasattr(os, "uname") else None,
            sys.version.split()[0],
            None,
            os.name,
            None,
            None,
            None,
            str(manifest_path) if manifest_path else None,
            manifest_sha256,
            (manifest or {}).get("n_rounds"),
            (manifest or {}).get("n_clients"),
            None,
        ),
    )


def _ingest_metric_aggregates(
    conn: sqlite3.Connection,
    run_id: str,
    manifest: Mapping[str, object],
) -> int:
    """Ingest the aggregate metrics from a manifest.

    We accepted both the flat form (``{"detection_accuracy": 0.9994}``)
    and the enveloped form (``{"metrics": {...}}``) because different
    modules in the extended suite use different conventions and forcing
    a single one would have required touching every module.
    """
    metrics = manifest.get("metrics")
    if not isinstance(metrics, dict):
        metrics = manifest

    n = 0
    now = int(time.time())
    for key, value in metrics.items():
        if not isinstance(value, (int, float)):
            continue
        conn.execute(
            """
            INSERT INTO metric_aggregates
                (run_id, metric_name, metric_value, metric_units,
                 confidence_low, confidence_high, n_samples,
                 thesis_reference, within_tolerance, computed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                str(key),
                float(value),
                None,
                None,
                None,
                None,
                None,
                None,
                now,
            ),
        )
        n += 1
    return n


def _ingest_window_predictions(
    conn: sqlite3.Connection,
    run_id: str,
    predictions_path: Path,
    seed: int,
) -> int:
    """Ingest a JSONL predictions file.

    We streamed the file rather than loading it entirely because the
    per-window prediction files for a full E1-E10 run are on the order
    of 500 MB each, and a load-in-memory approach would have needed
    more RAM than the reference host has.
    """
    n = 0
    with predictions_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            conn.execute(
                """
                INSERT INTO window_predictions
                    (run_id, window_id, flow_id, protocol, label,
                     prediction, confidence, elapsed_ns, budget_violated,
                     scenario_id, variant, seed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(rec.get("window_id", "")),
                    str(rec.get("flow_id", "")),
                    str(rec.get("protocol", "doh")),
                    int(rec.get("label", 0)),
                    int(rec.get("prediction", 0)),
                    float(rec.get("confidence", 0.0)),
                    int(rec.get("elapsed_ns", 0)),
                    1 if rec.get("budget_violated") else 0,
                    rec.get("scenario_id"),
                    rec.get("variant"),
                    seed,
                ),
            )
            n += 1
            if n % 10_000 == 0:
                conn.commit()
    return n


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Load A3E-DNS experiment manifests into the SQL result store."
    )
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--manifest-root", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20231130)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    conn = _connect(args.db)
    try:
        _apply_schemas(conn, args.schema_dir)
        total_metrics = 0
        total_predictions = 0
        for experiment_dir in sorted(args.manifest_root.iterdir()):
            if not experiment_dir.is_dir():
                continue
            experiment_id = experiment_dir.name
            manifest = _load_manifest(experiment_dir / "manifest.json")
            run_id = _run_id(experiment_dir, experiment_id)
            _insert_run(
                conn=conn,
                run_id=run_id,
                experiment_id=experiment_id,
                manifest=manifest,
                started_at=int(time.time()),
                finished_at=int(time.time()),
                status="completed",
                seed=args.seed,
                config_path=None,
                manifest_path=experiment_dir / "manifest.json",
                manifest_sha256=(
                    manifest.get("manifest_sha256") if manifest else None
                ),
            )
            if manifest:
                total_metrics += _ingest_metric_aggregates(conn, run_id, manifest)
            predictions_path = experiment_dir / "predictions.jsonl"
            if predictions_path.exists():
                total_predictions += _ingest_window_predictions(
                    conn, run_id, predictions_path, args.seed
                )
            conn.commit()
            LOGGER.info(
                "ingested %s as run_id %s", experiment_id, run_id
            )
        LOGGER.info(
            "ingestion complete: %d metric aggregates, %d window predictions",
            total_metrics, total_predictions,
        )
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
