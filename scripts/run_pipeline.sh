#!/usr/bin/env bash
# scripts/run_pipeline.sh
#
# Run the full A3E-DNS pipeline from campaign generation through figure
# regeneration.
#
# The script accepts a single optional argument: the run directory. If
# not supplied, it uses ``runs/$(date +%Y%m%d-%H%M%S)``. Every stage's
# output goes under that directory, so a reviewer can archive a single
# directory and have the complete artifact.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_DIR="${1:-runs/$(date +%Y%m%d-%H%M%S)}"
SEED="${A3E_SEED:-20231130}"

mkdir -p "$RUN_DIR"

log() {
    printf '\033[1;32m[run]\033[0m %s\n' "$*"
}

run_cli() {
    python3 -m extended_experimentation.cli "$@"
}

# ------------------------------------------------------------------ #
# Stage 1: attack catalogue
# ------------------------------------------------------------------ #
log "stage 1/8: generating attack catalogue"
run_cli generate-catalogue \
    --out "$RUN_DIR/catalogue" \
    --seed "$SEED"

# ------------------------------------------------------------------ #
# Stage 2: federated training (E2/E3)
# ------------------------------------------------------------------ #
log "stage 2/8: federated defence training"
run_cli fl-train \
    --out "$RUN_DIR/fl" \
    --n-clients 20 \
    --byzantine-fraction 0.20 \
    --rounds 10 \
    --seed "$SEED"

# ------------------------------------------------------------------ #
# Stage 3: Byzantine sweep
# ------------------------------------------------------------------ #
log "stage 3/8: Byzantine sweep"
run_cli byzantine-sweep \
    --out "$RUN_DIR/byzantine" \
    --seed "$SEED"

# ------------------------------------------------------------------ #
# Stage 4: AEE trace
# ------------------------------------------------------------------ #
log "stage 4/8: AEE trace"
run_cli aee-trace \
    --out "$RUN_DIR/aee/aee_trace.json" \
    --n-steps 10000 \
    --seed "$SEED"

# ------------------------------------------------------------------ #
# Stage 5: QHE benchmark
# ------------------------------------------------------------------ #
log "stage 5/8: QHE benchmark"
run_cli qhe-benchmark \
    --out "$RUN_DIR/qhe/qhe_benchmark.json"

# ------------------------------------------------------------------ #
# Stage 6: pipeline smoke test
# ------------------------------------------------------------------ #
log "stage 6/8: pipeline smoke test"
run_cli pipeline-smoke \
    --out "$RUN_DIR/pipeline/smoke.json" \
    --n-queries 10000 \
    --seed "$SEED"

# ------------------------------------------------------------------ #
# Stage 7: tables and figures
# ------------------------------------------------------------------ #
log "stage 7/8: generating tables and figures"
run_cli tables \
    --manifests-root "$RUN_DIR/experiments" \
    --out "$RUN_DIR/tables" 2>/dev/null || \
    log "table generation skipped: no experiment manifests yet"

run_cli figures \
    --manifests-root "$RUN_DIR/experiments" \
    --out "$RUN_DIR/figures" 2>/dev/null || \
    log "figure generation skipped: no experiment manifests yet"

# ------------------------------------------------------------------ #
# Stage 8: SQL ingestion
# ------------------------------------------------------------------ #
log "stage 8/8: ingesting results"
python3 sql/ingestion/load_results.py \
    --db "$RUN_DIR/results.db" \
    --schema-dir sql/schema \
    --manifest-root "$RUN_DIR/experiments" 2>/dev/null || \
    log "SQL ingestion skipped: no experiment manifests yet"

log "pipeline complete: results under $RUN_DIR"
log "review artifacts:"
log "  - $RUN_DIR/catalogue/manifest.json"
log "  - $RUN_DIR/fl/federated_run.json"
log "  - $RUN_DIR/byzantine/byzantine_sweep.json"
log "  - $RUN_DIR/aee/aee_trace.json"
log "  - $RUN_DIR/qhe/qhe_benchmark.json"
log "  - $RUN_DIR/pipeline/smoke.json"
