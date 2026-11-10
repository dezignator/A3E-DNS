# ============================================================
# A3E-DNS — Makefile
# Thesis artifact (Chapter 6)
# ============================================================
# Targets map 1:1 to REPRODUCIBILITY_CHECKLIST.md tiers:
#   make toy     -> Tier A  (~2 min,  CPU-only, synthetic data)
#   make medium  -> Tier B  (~45 min, CPU-only, A100 emulated)
#   make full    -> Tiers A+B+D (~6-9 h, real data)
#   make verify  -> checks outputs against expected_outputs/
# ============================================================

SHELL          := /bin/bash
.SHELLFLAGS    := -eu -o pipefail -c
.DEFAULT_GOAL  := help

PYTHON         ?= python3.11
PIP            := $(PYTHON) -m pip
MODE           ?= toy
TOLERANCE      ?= 1e-4
DEVICE         ?= cpu

# ---------- Help ----------
.PHONY: help
help:
	@echo ""
	@echo "A3E-DNS — Thesis artifact (Chapter 6)"
	@echo "-----------------------------------"
	@echo "  make toy       Tier A  — ~2 min,   synthetic data, CPU-only"
	@echo "  make medium    Tier B  — ~45 min,  A100 emulated, CPU-only"
	@echo "  make full      Tier A+B+D — 6–9 h, real 32 GB Zenodo + DoH + DoQ"
	@echo "  make verify    Compare outputs against expected_outputs/"
	@echo ""
	@echo "  make install   Install deps + editable package"
	@echo "  make data      Download datasets (MODE=toy|full)"
	@echo "  make preprocess Preprocess datasets (MODE=full)"
	@echo "  make train     Train A3E-DNS (MODE=toy|full)"
	@echo "  make tables    Reproduce all tables in Chapter 6"
	@echo "  make figures   Reproduce all figures in Chapter 6"
	@echo "  make test      Run unit + integration tests"
	@echo "  make lint      Run ruff + mypy"
	@echo "  make docker    Build the CPU image"
	@echo "  make compose   Bring up the 4-node testbed"
	@echo "  make compose-down  Tear down the 4-node testbed"
	@echo "  make clean     Remove build artifacts"
	@echo ""

# ---------- Install ----------
.PHONY: install
install:
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -r requirements.txt
	$(PYTHON) setup.py develop

# ---------- Data ----------
.PHONY: data
data:
	$(PYTHON) data/download_datasets.py --mode $(MODE) $(if $(filter full,$(MODE)),--verify-sha256,)

.PHONY: preprocess
preprocess:
ifeq ($(MODE),full)
	$(PYTHON) data/preprocess_zenodo.py --mode full
	$(PYTHON) data/preprocess_doh_realworld.py --mode full
	$(PYTHON) data/preprocess_kosekmi_doq.py --mode full
else
	@echo "preprocess: skipping (MODE=$(MODE), only 'full' needs preprocessing)"
endif

# ---------- Train ----------
.PHONY: train
train:
	$(PYTHON) scripts/train_a3e.py --mode $(MODE) --device $(DEVICE)

# ---------- Tables ----------
.PHONY: tables
tables:
	$(PYTHON) scripts/reproduce_tables/table_27_commands.py        --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_28_threat_intel.py    --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_29_compliance.py      --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_30_taxonomy.py        --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_31_injection_pipeline.py --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_32_simulation_matrix.py  --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_33_performance.py     --mode $(MODE)
	$(PYTHON) scripts/reproduce_tables/table_34a_component_map.py  --mode $(MODE)

# ---------- Figures ----------
.PHONY: figures
figures:
	$(PYTHON) scripts/reproduce_figures/figure_14_architecture.py  --mode $(MODE)
	$(PYTHON) scripts/reproduce_figures/figure_15_aee_analysis.py  --mode $(MODE)
	$(PYTHON) scripts/reproduce_figures/figure_16_performance.py   --mode $(MODE)
	$(PYTHON) scripts/reproduce_figures/figure_17_testbed.py       --mode $(MODE)
	$(PYTHON) scripts/reproduce_figures/figure_18_comparison.py    --mode $(MODE)
	$(PYTHON) scripts/reproduce_figures/figure_19_performance.py   --mode $(MODE)

# ---------- Reproduce (tables + figures) ----------
.PHONY: reproduce
reproduce: tables figures

# ---------- Top-level targets (Tier A / B / D) ----------
.PHONY: toy medium full
toy:
	$(MAKE) MODE=toy    data train reproduce verify

medium:
	$(MAKE) MODE=medium data train reproduce verify

full:
	$(MAKE) MODE=full   data preprocess train reproduce verify

# ---------- Verify ----------
.PHONY: verify
verify:
	$(PYTHON) expected_outputs/verification_script.py --all --tolerance $(TOLERANCE)

.PHONY: verify-cpu
verify-cpu:
	$(PYTHON) expected_outputs/verification_script.py --all --cpu-only --tolerance $(TOLERANCE)

# ---------- Tests ----------
.PHONY: test
test:
	$(PYTHON) -m pytest tests/ -v --timeout=600 -p no:cacheprovider

.PHONY: test-unit
test-unit:
	$(PYTHON) -m pytest tests/unit/ -v --timeout=300

.PHONY: test-integration
test-integration:
	$(PYTHON) -m pytest tests/integration/ -v --timeout=900

# ---------- Lint ----------
.PHONY: lint
lint:
	$(PYTHON) -m ruff check src/ scripts/ tests/
	$(PYTHON) -m mypy src/ --ignore-missing-imports

# ---------- Docker ----------
.PHONY: docker
docker:
	docker build -f Dockerfile -t a3e-dns:1.0.0 .

.PHONY: docker-gpu
docker-gpu:
	docker build -f Dockerfile.gpu -t a3e-dns:1.0.0-gpu .

# ---------- Compose (4-node testbed) ----------
.PHONY: compose
compose:
	docker compose -f docker-compose.yml up -d --build

.PHONY: compose-logs
compose-logs:
	docker compose -f docker-compose.yml logs -f

.PHONY: compose-down
compose-down:
	docker compose -f docker-compose.yml down -v

# ---------- Clean ----------
.PHONY: clean
clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "clean: done"

.PHONY: clean-outputs
clean-outputs:
	rm -rf outputs/ results/ artifacts/ reports/ tmp/ temp/
	@echo "clean-outputs: done (expected_outputs/ untouched)"
