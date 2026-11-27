-- sql/schema/03_attacks.sql
--
-- Attack catalogue and Byzantine attack history.
--
-- We separated these two tables from the metrics schema because they
-- describe what the experiment attacked, not what the detector
-- produced. Keeping them separate means the same attack catalogue can
-- be reused across multiple runs (for example, an ablation sweep that
-- varies only the detector) without duplicating the catalogue rows.

CREATE TABLE IF NOT EXISTS attack_scenarios (
    scenario_id         TEXT PRIMARY KEY,
    family              TEXT NOT NULL,
    description         TEXT NOT NULL,
    thesis_reference    TEXT NOT NULL,
    protocols           TEXT NOT NULL  -- comma-separated DoH/DoT/DoQ
);

INSERT OR IGNORE INTO attack_scenarios
    (scenario_id, family, description, thesis_reference, protocols)
VALUES
    ('S1-Timing',        'timing',        'Inter-arrival distribution drift',         'Table 32 S1',  'doh,dot,doq'),
    ('S2-Tunnel',        'tunnel',        'High-entropy label tunnel',                'Table 32 S2',  'doh,dot,doq'),
    ('S4-Quantum',       'quantum',       'Malformed PQ key-exchange parameters',     'Table 32 S4',  'doh,dot,doq'),
    ('S5-Evasion',       'evasion',       'Tunnel perturbed toward benign',           'Table 32 S5',  'doh,dot,doq'),
    ('S6-Beacon',        'beacon',        'Periodic command-and-control beacon',      'Table 31',     'doh,doq'),
    ('S7-Fragmentation', 'fragmentation', 'Payload fragmented across responses',      'Table 31',     'dot,doq'),
    ('S8-PaddingAbuse',  'padding_abuse', 'Excessive padding hides boundaries',       'Table 31',     'doh,dot'),
    ('S9-CachePoison',   'cache_poison',  'Low-TTL records force cache eviction',     'Table 31',     'doh,dot,doq'),
    ('S10-SideChannel',  'side_channel',  'Timing and direction side channel',        'Table 32 S10', 'doh,doq'),
    ('DoH-MUX',          'stream_mux',    'Malicious queries in HTTP/2 stream',       'Table 31',     'doh');

CREATE TABLE IF NOT EXISTS attack_flows (
    flow_id             TEXT PRIMARY KEY,
    scenario_id         TEXT NOT NULL,
    variant             TEXT NOT NULL
                        CHECK (variant IN ('baseline','low_and_slow','adaptive_blend')),
    protocol            TEXT NOT NULL
                        CHECK (protocol IN ('doh','dot','doq')),
    label               INTEGER NOT NULL CHECK (label IN (0,1)),
    severity            REAL NOT NULL,
    n_windows           INTEGER NOT NULL,
    generated_at        INTEGER NOT NULL,
    FOREIGN KEY (scenario_id) REFERENCES attack_scenarios(scenario_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_flows_scenario
    ON attack_flows(scenario_id, variant);

CREATE TABLE IF NOT EXISTS byzantine_rounds (
    round_pk            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT NOT NULL,
    round_index         INTEGER NOT NULL,
    n_clients           INTEGER NOT NULL,
    n_byzantine         INTEGER NOT NULL,
    aggregator          TEXT NOT NULL
                        CHECK (aggregator IN ('mean','median','trimmed_mean','krum')),
    mean_attack_ratio   REAL NOT NULL,
    max_attack_ratio    REAL NOT NULL,
    aggregate_accuracy  REAL NOT NULL,
    aggregate_fpr       REAL NOT NULL,
    dp_epsilon          REAL,
    computed_at         INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_byzantine_rounds_run_round
    ON byzantine_rounds(run_id, round_index);

-- Per-client strategy for a run. Stored once per run, not per round,
-- because the strategy assignment is fixed at run construction.
CREATE TABLE IF NOT EXISTS byzantine_clients (
    run_id              TEXT NOT NULL,
    client_index        INTEGER NOT NULL,
    strategy            TEXT NOT NULL,
    schedule            TEXT NOT NULL,
    base_magnitude      REAL NOT NULL,
    PRIMARY KEY (run_id, client_index),
    FOREIGN KEY (run_id) REFERENCES experiment_runs(run_id) ON DELETE CASCADE
);
