#!/usr/bin/env bash
# ============================================================
# A3E-DNS — reproduce_all.sh
# Thesis artifact (Chapter 6)
# ============================================================
# Runs every table and figure script in order, then verifies the
# outputs against expected_outputs/.
#
# Usage:
#   bash scripts/reproduce_all.sh --mode toy
#   bash scripts/reproduce_all.sh --mode medium
#   bash scripts/reproduce_all.sh --mode full
#
# The script fails fast on the first error (set -euo pipefail).
# ============================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# ---------- Defaults ----------
MODE="${A3E_DNS_MODE:-toy}"
TOLERANCE="${A3E_TOLERANCE:-1e-4}"
PYTHON="${A3E_PYTHON:-python3.11}"

# ---------- Parse args ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            MODE="$2"; shift 2 ;;
        --tolerance)
            TOLERANCE="$2"; shift 2 ;;
        --python)
            PYTHON="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: bash scripts/reproduce_all.sh [--mode toy|medium|full] [--tolerance 1e-4]"
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

case "${MODE}" in
    toy|medium|full) ;;
    *) echo "Invalid --mode '${MODE}' (expected toy|medium|full)" >&2; exit 2 ;;
esac

echo "============================================================"
echo "A3E-DNS reproduce_all.sh"
echo "  mode      : ${MODE}"
echo "  tolerance : ${TOLERANCE}"
echo "  python    : ${PYTHON}"
echo "  repo root : ${REPO_ROOT}"
echo "============================================================"

# ---------- Helpers ----------
step() {
    local name="$1"; shift
    echo ""
    echo ">>> [$(date -u +%H:%M:%S)] ${name}"
    "$@"
}

# ---------- Tables ----------
step "Table 27 — commands"        "${PYTHON}" scripts/reproduce_tables/table_27_commands.py --mode "${MODE}"
step "Table 28 — threat intel"    "${PYTHON}" scripts/reproduce_tables/table_28_threat_intel.py --mode "${MODE}"
step "Table 29 — compliance"      "${PYTHON}" scripts/reproduce_tables/table_29_compliance.py --mode "${MODE}"
step "Table 30 — taxonomy"        "${PYTHON}" scripts/reproduce_tables/table_30_taxonomy.py --mode "${MODE}"
step "Table 31 — injection"       "${PYTHON}" scripts/reproduce_tables/table_31_injection_pipeline.py --mode "${MODE}"
step "Table 32 — simulation"      "${PYTHON}" scripts/reproduce_tables/table_32_simulation_matrix.py --mode "${MODE}"
step "Table 33 — performance"     "${PYTHON}" scripts/reproduce_tables/table_33_performance.py --mode "${MODE}"
step "Table 34a — component map"  "${PYTHON}" scripts/reproduce_tables/table_34a_component_map.py --mode "${MODE}"

# ---------- Figures ----------
step "Figure 14 — architecture"   "${PYTHON}" scripts/reproduce_figures/figure_14_architecture.py --mode "${MODE}"
step "Figure 15 — AEE analysis"   "${PYTHON}" scripts/reproduce_figures/figure_15_aee_analysis.py --mode "${MODE}"
step "Figure 16 — performance (4 panels)" "${PYTHON}" scripts/reproduce_figures/figure_16_performance.py --mode "${MODE}"
step "Figure 17 — testbed"        "${PYTHON}" scripts/reproduce_figures/figure_17_testbed.py --mode "${MODE}"
step "Figure 18 — comparison"     "${PYTHON}" scripts/reproduce_figures/figure_18_comparison.py --mode "${MODE}"
step "Figure 19 — performance (6 panels)" "${PYTHON}" scripts/reproduce_figures/figure_19_performance.py --mode "${MODE}"

# ---------- Verify ----------
step "verify against expected_outputs/" \
    "${PYTHON}" expected_outputs/verification_script.py --all --tolerance "${TOLERANCE}"

echo ""
echo "============================================================"
echo "All tables and figures reproduced and verified."
echo "============================================================"
