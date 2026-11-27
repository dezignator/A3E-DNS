#!/usr/bin/env bash
# scripts/run_benchmarks.sh
#
# Run the performance benchmarks that back the E5/E6 latency and
# throughput claims.
#
# Unlike run_pipeline.sh, this script runs each benchmark multiple
# times and aggregates the results. That was necessary because the
# latency benchmark measures a P99 that is sensitive to warm-up and
# scheduling noise; a single run's P99 can vary by 20 %. The script
# takes the median of five runs, which matches the methodology the
# thesis documents.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_DIR="${1:-runs/benchmarks-$(date +%Y%m%d-%H%M%S)}"
REPETITIONS="${A3E_BENCHMARK_REPS:-5}"
SEED="${A3E_SEED:-20231130}"

mkdir -p "$RUN_DIR"

log() {
    printf '\033[1;35m[bench]\033[0m %s\n' "$*"
}

for i in $(seq 1 "$REPETITIONS"); do
    log "repetition $i/$REPETITIONS: pipeline smoke"
    python3 -m extended_experimentation.cli pipeline-smoke \
        --out "$RUN_DIR/smoke-$i.json" \
        --n-queries 50000 \
        --seed "$SEED"
done

log "aggregating results"
python3 - <<PY
import json
import statistics
from pathlib import Path

run_dir = Path("$RUN_DIR")
samples = []
for path in sorted(run_dir.glob("smoke-*.json")):
    samples.append(json.loads(path.read_text()))

p99 = [s["latency_ms"]["p99"] for s in samples]
median = [s["latency_ms"]["median"] for s in samples]
throughput = [s["throughput_qps_estimate"] for s in samples]

summary = {
    "n_repetitions": len(samples),
    "p99_ms_median": statistics.median(p99),
    "p99_ms_min": min(p99),
    "p99_ms_max": max(p99),
    "median_ms_median": statistics.median(median),
    "throughput_qps_median": statistics.median(throughput),
}
(run_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
PY

log "benchmark summary written to $RUN_DIR/benchmark_summary.json"
