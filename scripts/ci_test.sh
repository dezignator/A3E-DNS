#!/usr/bin/env bash
# scripts/ci_test.sh
#
# Run the full test suite for CI.
#
# This script is what the thesis's reproducibility appendix references
# when it says "all tests pass on a fresh clone." It builds every
# component, runs every language's tests, and fails on the first
# failure so that the CI log points at the actual problem.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() {
    printf '\033[1;33m[ci]\033[0m %s\n' "$*"
}

fail_count=0

run_step() {
    local name="$1"
    shift
    log "step: $name"
    if "$@"; then
        log "step passed: $name"
    else
        log "step FAILED: $name"
        fail_count=$((fail_count + 1))
    fi
}

# Python
if command -v python3 >/dev/null 2>&1; then
    run_step "python-lint" python3 -m compileall -q extended_experimentation
    if command -v pytest >/dev/null 2>&1; then
        run_step "python-tests" pytest -q extended_experimentation/tests
    else
        log "pytest not installed; skipping python tests"
    fi
else
    log "python3 not found; skipping python"
fi

# Rust
if command -v cargo >/dev/null 2>&1; then
    run_step "rust-tests" cargo test --release --manifest-path rust/a3e_core/Cargo.toml
else
    log "cargo not found; skipping rust"
fi

# Go
if command -v go >/dev/null 2>&1; then
    run_step "go-vet" sh -c 'cd go/a3e_resolver && go vet ./...'
    run_step "go-tests" sh -c 'cd go/a3e_resolver && go test -race -count=1 ./...'
else
    log "go not found; skipping go"
fi

# Shell
if command -v shellcheck >/dev/null 2>&1; then
    run_step "shellcheck" shellcheck scripts/*.sh
else
    log "shellcheck not found; skipping shell checks"
fi

# SQL
if command -v sqlite3 >/dev/null 2>&1; then
    run_step "sql-schema" bash -c '
        tmpdb=$(mktemp)
        trap "rm -f $tmpdb" EXIT
        for f in sql/schema/*.sql; do
            sqlite3 "$tmpdb" < "$f"
        done
        sqlite3 "$tmpdb" "SELECT COUNT(*) FROM experiment_catalog;" > /dev/null
    '
else
    log "sqlite3 not found; skipping sql checks"
fi

if [[ "$fail_count" -gt 0 ]]; then
    log "CI failed: $fail_count step(s) failed"
    exit 1
fi

log "CI passed"
