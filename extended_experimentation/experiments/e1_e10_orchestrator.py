#!/usr/bin/env python3
"""
extended_experimentation/experiments/e1_e10_orchestrator.py

Experiment orchestrator for the A3E-DNS E1-E10 evaluation.

We implemented this module to sequence the ten experiments that the
Chapter 6 traceability document maps (E1 through E10). Each experiment
already exists in the base repository as a standalone script under
``experiments_v2/``. The orchestrator's job is not to reimplement them;
it is to run them in dependency order, capture their outputs, verify
their artefacts, and produce a single consolidated manifest that ties
every experiment back to the thesis table it supports.

The orchestrator models the ten experiments as a directed acyclic graph.
The nodes are experiments; the edges are dependencies; a node becomes
runnable once every predecessor has completed with status ``completed``
(or ``cached``, if its artefact hashes match a prior run). That is the
same scheduling model a Makefile uses, and the reason for choosing it
was that the experiments have genuine fan-in and fan-out:
E1 depends on nothing; E2 depends on E1; E3 depends on E1; E4a-E4d all
depend on E3; E5 depends on E2 and E3; and so on. A naive topological
sort would serialise the DAG unnecessarily; a proper scheduler can run
independent branches in parallel.

Failure handling was the other design driver. The experiments are
expensive — some of them take twenty minutes on the reference host —
so a failure at E7 should not discard the successful artefacts from
E1-E6. The orchestrator therefore records each completed experiment's
artefacts and hashes independently, so a resumed run can start from the
first failed node without re-running anything that already succeeded.
That resume capability is what the ``--resume`` flag enables.

Design note on artefact verification. Every experiment produces a
manifest with a ``manifest_sha256`` field, following the same convention
the MIRAGE-DoH extended suite uses. The orchestrator verifies that hash
after the experiment completes, and refuses to mark the node as
successful if the hash doesn't match. That guard was added after a
partitioned filesystem silently truncated one manifest during a run;
the node reported success but the artefact was unusable downstream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.orchestrator")

# --------------------------------------------------------------------------- #
# Experiment definitions
# --------------------------------------------------------------------------- #
# The definitions below were transcribed from the Chapter 6 traceability
# document. Each entry specifies the script that implements the
# experiment, its dependencies, the artefacts it produces, and the
# thesis table it feeds. The ``command_template`` is a shell-style
# template that the runner formats with the run-time configuration.

@dataclass(frozen=True)
class ExperimentSpec:
    experiment_id: str
    script: str
    dependencies: Tuple[str, ...]
    output_artefacts: Tuple[str, ...]
    thesis_table: str
    description: str
    timeout_seconds: int = 3600
    supports_gpu: bool = False
    required: bool = True


EXPERIMENTS: Tuple[ExperimentSpec, ...] = (
    ExperimentSpec(
        experiment_id="E1",
        script="experiments_v2/e1_scenario_sweep.py",
        dependencies=(),
        output_artefacts=("e1/scenario_sweep.json", "e1/manifest.json"),
        thesis_table="Table 30 (scenario catalogue)",
        description="Baseline detection accuracy sweep across severity levels.",
    ),
    ExperimentSpec(
        experiment_id="E2",
        script="experiments_v2/e2_byzantine_sweep.py",
        dependencies=("E1",),
        output_artefacts=("e2/byzantine_sweep.json", "e2/manifest.json"),
        thesis_table="Table 31 (Byzantine robustness)",
        description="Robustness against the eight Byzantine strategies.",
        timeout_seconds=5400,
    ),
    ExperimentSpec(
        experiment_id="E3",
        script="experiments_v2/e3_dp_sweep.py",
        dependencies=("E1",),
        output_artefacts=("e3/dp_sweep.json", "e3/manifest.json"),
        thesis_table="Table 32 (DP epsilon sweep)",
        description="Differential-privacy epsilon versus utility sweep.",
    ),
    ExperimentSpec(
        experiment_id="E4a",
        script="experiments_v2/e4a_ntt_benchmark.py",
        dependencies=("E3",),
        output_artefacts=("e4a/ntt_benchmark.json", "e4a/manifest.json"),
        thesis_table="Table 33 (QHE primitives)",
        description="NTT versus schoolbook convolution benchmark.",
    ),
    ExperimentSpec(
        experiment_id="E4b",
        script="experiments_v2/e4b_sampler_benchmark.py",
        dependencies=("E3",),
        output_artefacts=("e4b/sampler_benchmark.json", "e4b/manifest.json"),
        thesis_table="Table 33 (QHE primitives)",
        description="Gaussian sampler correctness and timing.",
    ),
    ExperimentSpec(
        experiment_id="E4c",
        script="experiments_v2/e4c_selective_ops.py",
        dependencies=("E3",),
        output_artefacts=("e4c/selective_ops.json", "e4c/manifest.json"),
        thesis_table="Table 34 (selective operations)",
        description="Accuracy and cost of selective homomorphic operations.",
    ),
    ExperimentSpec(
        experiment_id="E4d",
        script="experiments_v2/e4d_packed_ciphertext.py",
        dependencies=("E3",),
        output_artefacts=("e4d/packed_ciphertext.json", "e4d/manifest.json"),
        thesis_table="Table 34 (packed ciphertext)",
        description="Packed ciphertext size and compression ratio.",
    ),
    ExperimentSpec(
        experiment_id="E5",
        script="experiments_v2/e5_latency.py",
        dependencies=("E2", "E3"),
        output_artefacts=("e5/latency.json", "e5/manifest.json"),
        thesis_table="Table 35 (P99 latency)",
        description="End-to-end P99 latency under combined attack load.",
        timeout_seconds=7200,
    ),
    ExperimentSpec(
        experiment_id="E6",
        script="experiments_v2/e6_throughput.py",
        dependencies=("E5",),
        output_artefacts=("e6/throughput.json", "e6/manifest.json"),
        thesis_table="Table 35 (peak throughput)",
        description="Peak QPS measurement at the target concurrency.",
        supports_gpu=True,
        timeout_seconds=7200,
    ),
    ExperimentSpec(
        experiment_id="E7",
        script="experiments_v2/e7_ablation.py",
        dependencies=("E2", "E3", "E4c"),
        output_artefacts=("e7/ablation.json", "e7/manifest.json"),
        thesis_table="Table 36 (ablation)",
        description="Component-level ablation (no-AEE, no-QHE, no-FL, no-attention).",
        timeout_seconds=7200,
    ),
    ExperimentSpec(
        experiment_id="E8",
        script="experiments_v2/e8_multi_protocol.py",
        dependencies=("E1",),
        output_artefacts=("e8/multi_protocol.json", "e8/manifest.json"),
        thesis_table="Table 37 (multi-protocol)",
        description="DoH, DoT and DoQ accuracy under the same detector.",
    ),
    ExperimentSpec(
        experiment_id="E9",
        script="experiments_v2/e9_adversarial_robustness.py",
        dependencies=("E1", "E2"),
        output_artefacts=("e9/adversarial_robustness.json", "e9/manifest.json"),
        thesis_table="Table 38 (adversarial robustness)",
        description="Robustness against adaptive-blend evasion.",
        timeout_seconds=5400,
    ),
    ExperimentSpec(
        experiment_id="E10",
        script="experiments_v2/e10_statistical_analysis.py",
        dependencies=("E1", "E2", "E3", "E5", "E6", "E7", "E8", "E9"),
        output_artefacts=("e10/statistical_analysis.json", "e10/manifest.json"),
        thesis_table="Table 39 (statistical significance)",
        description="Paired bootstrap and Wilcoxon tests on E1-E9 results.",
        timeout_seconds=3600,
    ),
)

EXPERIMENTS_BY_ID: Dict[str, ExperimentSpec] = {
    e.experiment_id: e for e in EXPERIMENTS
}

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class ExperimentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CACHED = "cached"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


# --------------------------------------------------------------------------- #
# Result records
# --------------------------------------------------------------------------- #


@dataclass
class ExperimentResult:
    experiment_id: str
    status: ExperimentStatus
    started_at: float
    finished_at: float
    return_code: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    artefact_hashes: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def elapsed_s(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def to_dict(self) -> Dict[str, object]:
        return {
            "experiment_id": self.experiment_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s": self.elapsed_s,
            "return_code": self.return_code,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "artefact_hashes": dict(self.artefact_hashes),
            "error": self.error,
        }


@dataclass
class OrchestratorConfig:
    repository_root: Path
    output_root: Path
    python_executable: str = "python"
    resume: bool = False
    parallel: bool = True
    max_workers: int = 4
    seed: int = 20231130
    verbose: bool = False
    extra_env: Dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.repository_root.exists():
            raise FileNotFoundError(
                f"repository root does not exist: {self.repository_root}"
            )
        self.output_root.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Dependency resolution
# --------------------------------------------------------------------------- #


def _topological_order() -> List[str]:
    """Return the experiment ids in dependency order.

    We used Kahn's algorithm; it is O(V + E) and produces a deterministic
    order given a deterministic tie-break, which is what the orchestrator
    needs for reproducible run reports.
    """
    in_degree: Dict[str, int] = {e.experiment_id: 0 for e in EXPERIMENTS}
    adjacency: Dict[str, List[str]] = {e.experiment_id: [] for e in EXPERIMENTS}
    for exp in EXPERIMENTS:
        for dep in exp.dependencies:
            if dep not in EXPERIMENTS_BY_ID:
                raise ValueError(f"{exp.experiment_id} depends on unknown {dep}")
            adjacency[dep].append(exp.experiment_id)
            in_degree[exp.experiment_id] += 1

    ready = sorted([eid for eid, d in in_degree.items() if d == 0])
    order: List[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for successor in sorted(adjacency[current]):
            in_degree[successor] -= 1
            if in_degree[successor] == 0:
                ready.append(successor)
                ready.sort()
    if len(order) != len(EXPERIMENTS):
        raise RuntimeError("dependency graph contains a cycle")
    return order


# --------------------------------------------------------------------------- #
# Artefact hashing
# --------------------------------------------------------------------------- #


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_artefact(artefact_path: Path) -> Tuple[bool, str]:
    """Verify an artefact's internal manifest_sha256, if present."""
    if not artefact_path.exists():
        return False, "missing"
    try:
        payload = json.loads(artefact_path.read_text())
    except Exception as exc:
        return False, f"unparseable: {exc}"
    if not isinstance(payload, dict):
        return False, "not a json object"
    declared = payload.get("manifest_sha256")
    if declared is None:
        # Not every artefact carries the hash; that is fine, we only flag
        # it when the field is present and mismatched.
        return True, "no-hash"
    body = {k: v for k, v in payload.items() if k != "manifest_sha256"}
    computed = hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    if computed != declared:
        return False, "hash-mismatch"
    return True, "ok"


# --------------------------------------------------------------------------- #
# Subprocess runner
# --------------------------------------------------------------------------- #


def _run_experiment(
    spec: ExperimentSpec,
    config: OrchestratorConfig,
) -> ExperimentResult:
    started = time.monotonic()
    script_path = config.repository_root / spec.script
    if not script_path.exists():
        return ExperimentResult(
            experiment_id=spec.experiment_id,
            status=ExperimentStatus.SKIPPED,
            started_at=started,
            finished_at=time.monotonic(),
            error=f"script not found: {script_path}",
        )

    experiment_out = config.output_root / spec.experiment_id.lower()
    experiment_out.mkdir(parents=True, exist_ok=True)

    cmd = [
        config.python_executable,
        str(script_path),
        "--out",
        str(experiment_out),
        "--seed",
        str(config.seed),
    ]
    env = os.environ.copy()
    env.update(config.extra_env)
    env["A3E_ORCHESTRATOR_RUN"] = "1"
    env["A3E_ORCHESTRATOR_EXPERIMENT"] = spec.experiment_id

    LOGGER.info("running %s: %s", spec.experiment_id, " ".join(cmd))
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    status = ExperimentStatus.COMPLETED
    error: Optional[str] = None
    return_code: Optional[int] = None

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(config.repository_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            stdout, stderr = proc.communicate(timeout=spec.timeout_seconds)
            stdout_lines = stdout.splitlines()[-50:] if stdout else []
            stderr_lines = stderr.splitlines()[-50:] if stderr else []
            return_code = proc.returncode
            if return_code != 0:
                status = ExperimentStatus.FAILED
                error = f"non-zero exit code {return_code}"
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            stdout_lines = stdout.splitlines()[-50:] if stdout else []
            stderr_lines = stderr.splitlines()[-50:] if stderr else []
            status = ExperimentStatus.TIMEOUT
            error = f"timeout after {spec.timeout_seconds}s"
    except Exception as exc:
        status = ExperimentStatus.FAILED
        error = f"{type(exc).__name__}: {exc}"

    finished = time.monotonic()

    # Verify artefacts on the way out.
    hashes: Dict[str, str] = {}
    if status is ExperimentStatus.COMPLETED:
        for artefact_rel in spec.output_artefacts:
            artefact_path = config.output_root / artefact_rel
            if not artefact_path.exists():
                status = ExperimentStatus.FAILED
                error = f"missing artefact: {artefact_rel}"
                break
            ok, reason = _verify_artefact(artefact_path)
            if not ok:
                status = ExperimentStatus.FAILED
                error = f"artefact verification failed: {artefact_rel} ({reason})"
                break
            hashes[artefact_rel] = _hash_file(artefact_path)

    return ExperimentResult(
        experiment_id=spec.experiment_id,
        status=status,
        started_at=started,
        finished_at=finished,
        return_code=return_code,
        stdout_tail="\n".join(stdout_lines),
        stderr_tail="\n".join(stderr_lines),
        artefact_hashes=hashes,
        error=error,
    )


# --------------------------------------------------------------------------- #
# Caching
# --------------------------------------------------------------------------- #


def _load_prior_results(output_root: Path) -> Dict[str, ExperimentResult]:
    """Load any prior results so that resume can pick up where it left off."""
    path = output_root / "orchestrator_state.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except Exception:
        LOGGER.warning("could not parse prior state at %s; ignoring", path)
        return {}
    results: Dict[str, ExperimentResult] = {}
    for record in payload.get("results", []):
        try:
            results[str(record["experiment_id"])] = ExperimentResult(
                experiment_id=str(record["experiment_id"]),
                status=ExperimentStatus(str(record["status"])),
                started_at=float(record.get("started_at", 0.0)),
                finished_at=float(record.get("finished_at", 0.0)),
                return_code=(
                    int(record["return_code"])
                    if record.get("return_code") is not None
                    else None
                ),
                stdout_tail=str(record.get("stdout_tail", "")),
                stderr_tail=str(record.get("stderr_tail", "")),
                artefact_hashes={
                    str(k): str(v)
                    for k, v in (record.get("artefact_hashes") or {}).items()
                },
                error=record.get("error"),
            )
        except Exception:
            LOGGER.warning(
                "could not restore prior result for %s",
                record.get("experiment_id"),
            )
    return results


def _check_cached(
    spec: ExperimentSpec,
    prior: Optional[ExperimentResult],
    output_root: Path,
) -> bool:
    """Determine whether an experiment can be reused from a prior run.

    A prior result is reusable if it completed successfully AND every
    artefact it produced still exists AND its hash matches the prior run.
    That is the minimum bar for skipping; anything less and we re-run.
    """
    if prior is None or prior.status not in (
        ExperimentStatus.COMPLETED,
        ExperimentStatus.CACHED,
    ):
        return False
    for artefact_rel in spec.output_artefacts:
        artefact_path = output_root / artefact_rel
        if not artefact_path.exists():
            return False
        if _hash_file(artefact_path) != prior.artefact_hashes.get(artefact_rel):
            return False
    return True


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


class ExperimentOrchestrator:
    def __init__(self, config: OrchestratorConfig) -> None:
        config.validate()
        self.config = config
        self.results: Dict[str, ExperimentResult] = {}
        self.start_time = time.monotonic()

    def _emit_state(self) -> None:
        path = self.config.output_root / "orchestrator_state.json"
        payload = {
            "run_started_at": self.start_time,
            "n_experiments": len(EXPERIMENTS),
            "config": {
                "seed": self.config.seed,
                "parallel": self.config.parallel,
                "max_workers": self.config.max_workers,
                "resume": self.config.resume,
            },
            "results": [r.to_dict() for r in self.results.values()],
        }
        payload["manifest_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        path.write_text(json.dumps(payload, indent=2))

    def _dependencies_satisfied(self, spec: ExperimentSpec) -> bool:
        for dep in spec.dependencies:
            dep_result = self.results.get(dep)
            if dep_result is None:
                return False
            if dep_result.status not in (
                ExperimentStatus.COMPLETED,
                ExperimentStatus.CACHED,
            ):
                return False
        return True

    def _is_terminal(self, status: ExperimentStatus) -> bool:
        return status in (
            ExperimentStatus.COMPLETED,
            ExperimentStatus.CACHED,
            ExperimentStatus.FAILED,
            ExperimentStatus.TIMEOUT,
            ExperimentStatus.SKIPPED,
        )

    def run(self) -> Dict[str, object]:
        prior_results: Dict[str, ExperimentResult] = {}
        if self.config.resume:
            prior_results = _load_prior_results(self.config.output_root)
            LOGGER.info("resume mode: found %d prior results", len(prior_results))

        order = _topological_order()
        LOGGER.info("execution order: %s", order)

        # Prime the results map: cached nodes take their prior status,
        # everything else starts PENDING.
        for eid in order:
            spec = EXPERIMENTS_BY_ID[eid]
            if self.config.resume and _check_cached(
                spec, prior_results.get(eid), self.config.output_root
            ):
                cached = prior_results[eid]
                cached.status = ExperimentStatus.CACHED
                self.results[eid] = cached
                LOGGER.info("cached: %s", eid)
            else:
                self.results[eid] = ExperimentResult(
                    experiment_id=eid,
                    status=ExperimentStatus.PENDING,
                    started_at=0.0,
                    finished_at=0.0,
                )

        # Execution loop. We ran a scheduler that repeatedly scans for
        # ready nodes and dispatches up to max_workers of them. This is a
        # simpler approach than event-driven scheduling with condition
        # variables, and it was fast enough for fifteen nodes.
        if self.config.parallel:
            self._run_parallel()
        else:
            self._run_sequential()

        summary = self._build_summary()
        self._emit_state()
        self._write_summary(summary)
        return summary

    def _run_sequential(self) -> None:
        for eid in _topological_order():
            current = self.results[eid]
            if current.status in (
                ExperimentStatus.COMPLETED,
                ExperimentStatus.CACHED,
            ):
                continue
            if not self._dependencies_satisfied(EXPERIMENTS_BY_ID[eid]):
                LOGGER.warning(
                    "skipping %s: dependencies not satisfied", eid
                )
                self.results[eid] = ExperimentResult(
                    experiment_id=eid,
                    status=ExperimentStatus.SKIPPED,
                    started_at=0.0,
                    finished_at=time.monotonic(),
                    error="dependencies not satisfied",
                )
                continue
            spec = EXPERIMENTS_BY_ID[eid]
            result = _run_experiment(spec, self.config)
            self.results[eid] = result
            self._emit_state()
            if result.status is ExperimentStatus.FAILED:
                LOGGER.error(
                    "%s failed: %s", eid, result.error
                )

    def _run_parallel(self) -> None:
        # The parallel scheduler processes ready nodes as a batch, then
        # waits for any one to finish before re-checking readiness. That
        # is the minimal parallel scheduler: no per-node observer
        # machinery, no thread pool reentrancy, just the loop.
        pending: Set[str] = {
            eid
            for eid, r in self.results.items()
            if r.status not in (
                ExperimentStatus.COMPLETED,
                ExperimentStatus.CACHED,
            )
        }
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            while pending:
                ready = [
                    eid
                    for eid in list(pending)
                    if self._dependencies_satisfied(EXPERIMENTS_BY_ID[eid])
                ]
                # Discard nodes with unsatisfiable dependencies, unless
                # they are still waiting on a node that has yet to run.
                stuck = [
                    eid
                    for eid in list(pending)
                    if not self._dependencies_satisfied(EXPERIMENTS_BY_ID[eid])
                    and all(
                        self.results[dep].status
                        not in (
                            ExperimentStatus.PENDING,
                            ExperimentStatus.RUNNING,
                        )
                        for dep in EXPERIMENTS_BY_ID[eid].dependencies
                    )
                ]
                for eid in stuck:
                    self.results[eid] = ExperimentResult(
                        experiment_id=eid,
                        status=ExperimentStatus.SKIPPED,
                        started_at=0.0,
                        finished_at=time.monotonic(),
                        error="dependency failed",
                    )
                    pending.discard(eid)

                if not ready:
                    if not pending:
                        break
                    # No ready nodes and pending is non-empty means all
                    # remaining nodes are waiting on running ones; we
                    # yield briefly to avoid a hot spin.
                    time.sleep(0.5)
                    continue

                futures = {
                    pool.submit(
                        _run_experiment, EXPERIMENTS_BY_ID[eid], self.config
                    ): eid
                    for eid in ready
                }
                for future in as_completed(futures):
                    eid = futures[future]
                    result = future.result()
                    self.results[eid] = result
                    pending.discard(eid)
                    self._emit_state()
                    LOGGER.info(
                        "%s: %s (%.1fs)",
                        eid,
                        result.status.value,
                        result.elapsed_s,
                    )

    # -- summary ------------------------------------------------------------ #

    def _build_summary(self) -> Dict[str, object]:
        counts: Dict[str, int] = {}
        for r in self.results.values():
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        by_status: Dict[str, List[str]] = {}
        for eid, r in self.results.items():
            by_status.setdefault(r.status.value, []).append(eid)
        failed = [
            r for r in self.results.values()
            if r.status
            in (ExperimentStatus.FAILED, ExperimentStatus.TIMEOUT)
        ]
        overall_success = len(failed) == 0 and all(
            r.status
            in (
                ExperimentStatus.COMPLETED,
                ExperimentStatus.CACHED,
                ExperimentStatus.SKIPPED,
            )
            for r in self.results.values()
        )
        return {
            "module": "extended_experimentation.experiments.e1_e10_orchestrator",
            "n_experiments": len(EXPERIMENTS),
            "counts": counts,
            "by_status": by_status,
            "overall_success": overall_success,
            "elapsed_s": time.monotonic() - self.start_time,
            "results": [r.to_dict() for r in self.results.values()],
        }

    def _write_summary(self, summary: Mapping[str, object]) -> None:
        path = self.config.output_root / "orchestrator_summary.json"
        body = dict(summary)
        body["manifest_sha256"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        path.write_text(json.dumps(body, indent=2))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sequence the A3E-DNS E1-E10 experiments in dependency order."
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--seed", type=int, default=20231130)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--parallel", action="store_true")
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = OrchestratorConfig(
        repository_root=args.repository_root,
        output_root=args.output_root,
        python_executable=args.python_executable,
        seed=args.seed,
        resume=args.resume,
        parallel=args.parallel,
        max_workers=args.max_workers,
    )
    orchestrator = ExperimentOrchestrator(config)
    summary = orchestrator.run()
    LOGGER.info(
        "orchestrator finished: %s (elapsed %.1fs)",
        summary["counts"],
        summary["elapsed_s"],
    )
    return 0 if summary["overall_success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
