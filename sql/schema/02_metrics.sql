-- sql/schema/02_metrics.sql
--
-- Per-window metrics and aggregate results.
--
-- We stored both the per-window predictions and the aggregates derived
-- from them, rather than only the aggregates. The reason is that the
-- significance harness recomputes the bootstrap and Wilcoxon tests from
-- the per-window data, and a schema that only kept the aggregates
-- would have made the harness dependent on the original JSONL files
-- surviving the archival step. Keeping the per-window rows in the
-- database made the whole analysis reproducible from a single SQLite
-- file.

CREATE TABLE IF NOT EXISTS metric_aggregates (
    aggregate_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL,
    metric_name         TEXT NOT NULL,
    metric_value        REAL NOT NULL,
    metric_units        TEXT,
    confidence_low      REAL,
    confidence_high     REAL,
    n_samples           INTEGER,
    thesis_reference    REAL,
    within_tolerance    INTEGER,
    computed_at         INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_metric_aggregates_run_metric
    ON metric_aggregates(run_id, metric_name);

-- Per-window predictions. One row per classified window.
--
-- The window_id is the flow_id emitted by the attack catalogue. That
-- is the join key between this table, the attack_flows table and the
-- significance harness's own artefacts.
CREATE TABLE IF NOT EXISTS window_predictions (
    prediction_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL,
    window_id           TEXT NOT NULL,
    flow_id             TEXT NOT NULL,
    protocol            TEXT NOT NULL
                        CHECK (protocol IN ('doh','dot','doq')),
    label               INTEGER NOT NULL CHECK (label IN (0,1)),
    prediction          INTEGER NOT NULL CHECK (prediction IN (0,1)),
    confidence          REAL NOT NULL,
    elapsed_ns          INTEGER,
    budget_violated     INTEGER NOT NULL DEFAULT 0,
    scenario_id         TEXT,
    variant             TEXT,
    seed                INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_window_predictions_run
    ON window_predictions(run_id);
CREATE INDEX IF NOT EXISTS idx_window_predictions_label
    ON window_predictions(run_id, label);
CREATE INDEX IF NOT EXISTS idx_window_predictions_protocol
    ON window_predictions(run_id, protocol);
CREATE INDEX IF NOT EXISTS idx_window_predictions_scenario
    ON window_predictions(run_id, scenario_id);

-- Per-scenario accuracy aggregates. Derived from window_predictions but
-- stored separately so that the frequent read path (the S1 table) does
-- not need a GROUP BY over the full prediction set.
CREATE TABLE IF NOT EXISTS scenario_aggregates (
    aggregate_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL,
    scenario_id         TEXT NOT NULL,
    variant             TEXT NOT NULL,
    n_windows           INTEGER NOT NULL,
    n_benign            INTEGER NOT NULL,
    n_attack            INTEGER NOT NULL,
    true_positives      INTEGER NOT NULL,
    false_positives     INTEGER NOT NULL,
    true_negatives      INTEGER NOT NULL,
    false_negatives     INTEGER NOT NULL,
    accuracy            REAL NOT NULL,
    false_positive_rate REAL NOT NULL,
    precision_score     REAL NOT NULL,
    recall              REAL NOT NULL,
    f1_score            REAL NOT NULL,
    computed_at         INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scenario_aggregates_run
    ON scenario_aggregates(run_id);

-- Latency percentiles per protocol. Stored alongside scenario
-- aggregates rather than derived because the per-window elapsed_ns
-- column is too coarse for the P99 assertion the thesis makes; the
-- percentile computation is expensive enough that storing it once is
-- worth the extra table.
CREATE TABLE IF NOT EXISTS latency_percentiles (
    percentile_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    p50_ns              INTEGER NOT NULL,
    p95_ns              INTEGER NOT NULL,
    p99_ns              INTEGER NOT NULL,
    p999_ns             INTEGER,
    max_ns              INTEGER NOT NULL,
    n_samples           INTEGER NOT NULL,
    computed_at         INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_latency_percentiles_run_proto
    ON latency_percentiles(run_id, protocol);
