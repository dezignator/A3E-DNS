-- sql/queries/byzantine_robustness.sql
--
-- Byzantine robustness sweep for the S2 table.
--
-- The query aggregates the per-round attack ratios into per-fraction
-- summaries. The aggregation is done over the byzantine_rounds table
-- rather than the raw predictions because the ratio is what the
-- robustness figure plots, and recomputing it from raw predictions
-- would have required the per-client per-round magnitudes which we
-- only store in the round table.

SELECT
    n_byzantine,
    n_clients,
    ROUND(CAST(n_byzantine AS REAL) / CAST(n_clients AS REAL), 3) AS byzantine_fraction,
    aggregator,
    COUNT(*) AS n_rounds,
    ROUND(AVG(mean_attack_ratio), 6) AS mean_attack_ratio,
    ROUND(AVG(max_attack_ratio), 6) AS mean_of_max_ratio,
    ROUND(MAX(max_attack_ratio), 6) AS global_max_ratio,
    ROUND(AVG(aggregate_accuracy), 6) AS mean_accuracy,
    ROUND(AVG(aggregate_fpr), 6) AS mean_fpr,
    ROUND(AVG(dp_epsilon), 4) AS mean_epsilon
FROM byzantine_rounds
WHERE run_id = :run_id
GROUP BY n_byzantine, n_clients, aggregator
ORDER BY byzantine_fraction, aggregator;
