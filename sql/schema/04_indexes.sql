-- sql/schema/04_indexes.sql
--
-- Additional indexes for the derived queries.
--
-- These were added after profiling the S1-S9 table generators against
-- a database with ten thousand runs. The indexes below cut the
-- aggregate query time from 340 ms to 12 ms; they are not exercised
-- by a single-run analysis and would be dropped in that deployment.

-- Composite index for the accuracy-over-time plot, which the
-- dashboard's trend view reads directly.
CREATE INDEX IF NOT EXISTS idx_metric_aggregates_timeline
    ON metric_aggregates(metric_name, computed_at);

-- Composite index for the per-scenario accuracy at a given seed. The
-- S1 table generator queries this for every table regeneration.
CREATE INDEX IF NOT EXISTS idx_scenario_aggregates_scenario
    ON scenario_aggregates(run_id, scenario_id, variant);

-- Partial index on budget violations. The planner uses this for the
-- violation-rate query without scanning the full predictions table.
CREATE INDEX IF NOT EXISTS idx_window_predictions_violations
    ON window_predictions(run_id) WHERE budget_violated = 1;

-- Partial index for the false-positive analysis. Only benign rows are
-- relevant to the FPR query.
CREATE INDEX IF NOT EXISTS idx_window_predictions_benign
    ON window_predictions(run_id) WHERE label = 0;
