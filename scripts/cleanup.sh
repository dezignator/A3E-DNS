#!/usr/bin/env bash
# scripts/cleanup.sh
#
# Remove build artefacts and any local runs.
#
# This is the script a developer runs before submitting a patch. It
# removes anything that a fresh `git status` would show as untracked
# from the build process, while leaving anything under `runs/` alone
# unless the caller passes --purge-runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PURGE_RUNS=0
for arg in "$@"; do
    if [[ "$arg" == "--purge-runs" ]]; then
        PURGE_RUNS=1
    fi
done

log() {
    printf '\033[1;36m[clean]\033[0m %s\n' "$*"
}

log "cleaning Rust"
if [[ -d rust/a3e_core/target ]]; then
    rm -rf rust/a3e_core/target
fi

log "cleaning Go"
if [[ -d go/a3e_resolver/bin ]]; then
    rm -rf go/a3e_resolver/bin
fi
if [[ -d go/a3e_resolver/internal/api/pb ]]; then
    find go/a3e_resolver/internal/api/pb -name '*.go' -delete
fi

log "cleaning Python"
find . -name '__pycache__' -type d -prune -exec rm -rf {} +
find . -name '*.pyc' -delete
find . -name '*.egg-info' -type d -prune -exec rm -rf {} +

log "cleaning temporary manifests"
find . -name '.orchestrator_state.json' -delete

if [[ "$PURGE_RUNS" == "1" ]]; then
    log "purging run directories"
    if [[ -d runs ]]; then
        rm -rf runs
    fi
else
    log "run directories preserved (use --purge-runs to remove)"
fi

log "cleanup complete"
