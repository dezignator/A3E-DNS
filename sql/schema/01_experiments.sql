-- sql/schema/01_experiments.sql
--
-- Experiment runs and metadata.
--
-- We modelled every execution of every experiment as a row in
-- experiment_runs. That was necessary because the E1-E10 orchestrator
-- can be invoked repeatedly with different seeds, different commit
-- hashes and different configurations, and the results need to be
-- joinable across those dimensions. A single "results" table without a
-- run identifier would have made it impossible to answer the question
-- "did the accuracy on this experiment change when we bumped the
-- seed?" — which is exactly the question a reviewer asks when
-- reproducing a thesis.
--
-- The schema is written for SQLite for local runs and PostgreSQL for
-- the reference deployment. The only portability concession is the
-- use of INTEGER for timestamps in SQLite and TIMESTAMPTZ in
-- PostgreSQL; the migration layer applies the correct DDL for each
-- backend.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS experiment_runs (
    run_id              TEXT PRIMARY KEY,
    experiment_id       TEXT NOT NULL,
    started_at          INTEGER NOT NULL,
    finished_at         INTEGER,
    status              TEXT NOT NULL
                        CHECK (status IN ('pending','running','completed','failed','timeout','cached')),
    seed                INTEGER NOT NULL,
    git_commit          TEXT,
    git_dirty           INTEGER NOT NULL DEFAULT 0,
    config_path         TEXT,
    config_hash         TEXT,
    hostname            TEXT,
    python_version      TEXT,
    rust_version        TEXT,
    os_name             TEXT,
    stdout_tail         TEXT,
    stderr_tail         TEXT,
    error_message       TEXT,
    manifest_path       TEXT,
    manifest_sha256     TEXT,
    n_rounds            INTEGER,
    n_clients           INTEGER,
    notes               TEXT
);

CREATE TABLE IF NOT EXISTS experiment_dependencies (
    run_id              TEXT NOT NULL,
    dependency_run_id   TEXT NOT NULL,
    PRIMARY KEY (run_id, dependency_run_id),
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (dependency_run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

-- The ten experiments the thesis reports. This table is fixed and is
-- populated by the migration; it does not change between runs.
CREATE TABLE IF NOT EXISTS experiment_catalog (
    experiment_id       TEXT PRIMARY KEY,
    script_path         TEXT NOT NULL,
    thesis_table        TEXT NOT NULL,
    description         TEXT NOT NULL,
    is_required         INTEGER NOT NULL DEFAULT 1
);

INSERT OR IGNORE INTO experiment_catalog
    (experiment_id, script_path, thesis_table, description, is_required)
VALUES
    ('E1',  'experiments_v2/e1_scenario_sweep.py',      'Table 30', 'Per-scenario detection sweep',              1),
    ('E2',  'experiments_v2/e2_byzantine_sweep.py',     'Table 31', 'Byzantine robustness sweep',                1),
    ('E3',  'experiments_v2/e3_dp_sweep.py',            'Table 32', 'DP epsilon sweep',                          1),
    ('E4a', 'experiments_v2/e4a_ntt_benchmark.py',      'Table 33', 'NTT benchmark',                             1),
    ('E4b', 'experiments_v2/e4b_sampler_benchmark.py',  'Table 33', 'Sampler benchmark',                         1),
    ('E4c', 'experiments_v2/e4c_selective_ops.py',      'Table 34', 'Selective homomorphic operations',          1),
    ('E4d', 'experiments_v2/e4d_packed_ciphertext.py',  'Table 34', 'Packed ciphertext compression',             1),
    ('E5',  'experiments_v2/e5_latency.py',             'Table 35', 'P99 latency',                               1),
    ('E6',  'experiments_v2/e6_throughput.py',          'Table 35', 'Peak throughput',                           1),
    ('E7',  'experiments_v2/e7_ablation.py',            'Table 36', 'Component ablation',                         1),
    ('E8',  'experiments_v2/e8_multi_protocol.py',      'Table 37', 'Multi-protocol accuracy',                   1),
    ('E9',  'experiments_v2/e9_adversarial_robustness.py','Table 38','Adversarial robustness',                    1),
    ('E10', 'experiments_v2/e10_statistical_analysis.py','Table 39','Statistical significance',                 1);
