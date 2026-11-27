-- sql/queries/aggregate_scenarios.sql
--
-- Per-scenario accuracy and FPR for the S1 table.
--
-- We used a single query rather than a stored procedure because the
-- query is called once per S1 regeneration and the SQLite planner
-- handles it well. The query takes a single parameter — the run_id —
-- which the ingestion helper binds at call time.

SELECT
    scenario_id,
    variant,
    COUNT(*) AS n_windows,
    SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END) AS n_benign,
    SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) AS n_attack,
    SUM(CASE WHEN label = 1 AND prediction = 1 THEN 1 ELSE 0 END) AS tp,
    SUM(CASE WHEN label = 0 AND prediction = 1 THEN 1 ELSE 0 END) AS fp,
    SUM(CASE WHEN label = 0 AND prediction = 0 THEN 1 ELSE 0 END) AS tn,
    SUM(CASE WHEN label = 1 AND prediction = 0 THEN 1 ELSE 0 END) AS fn,
    ROUND(
        CAST(SUM(CASE WHEN label = prediction THEN 1 ELSE 0 END) AS REAL)
        / CAST(COUNT(*) AS REAL),
        6
    ) AS accuracy,
    ROUND(
        CAST(SUM(CASE WHEN label = 0 AND prediction = 1 THEN 1 ELSE 0 END) AS REAL)
        / CAST(NULLIF(SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END), 0) AS REAL),
        6
    ) AS false_positive_rate,
    ROUND(
        CAST(SUM(CASE WHEN label = 1 AND prediction = 1 THEN 1 ELSE 0 END) AS REAL)
        / CAST(NULLIF(SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END), 0) AS REAL),
        6
    ) AS precision_score,
    ROUND(
        CAST(SUM(CASE WHEN label = 1 AND prediction = 1 THEN 1 ELSE 0 END) AS REAL)
        / CAST(NULLIF(SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END), 0) AS REAL),
        6
    ) AS recall,
    ROUND(
        2.0 *
        CAST(SUM(CASE WHEN label = 1 AND prediction = 1 THEN 1 ELSE 0 END) AS REAL)
        / CAST(NULLIF(
            SUM(CASE WHEN label = 1 AND prediction = 1 THEN 1 ELSE 0 END)
            + SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END)
            + SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END),
            0
        ) AS REAL),
        6
    ) AS f1_score
FROM window_predictions
WHERE run_id = :run_id
  AND scenario_id IS NOT NULL
GROUP BY scenario_id, variant
ORDER BY scenario_id, variant;
