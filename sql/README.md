# A3E-DNS result store

SQL schema, queries and ingestion helper for the E1–E10 experiment
results. The store exists so that the tables, figures and significance
tests in the Chapter 6 appendix can be regenerated from a single
database file rather than from a pile of JSONL manifests whose
integrity depends on every file surviving archival.

## Backends

The schema is written in SQLite dialect for local runs. The reference
deployment uses PostgreSQL; the migration layer applies the
PostgreSQL-specific type substitutions (`INTEGER` → `BIGINT` for
timestamps, `TIMESTAMPTZ` for `started_at` and `finished_at`) at
schema application time. Every query in `queries/` is portable between
the two backends without modification.

## Applying the schema

```bash
sqlite3 results.db < sql/schema/01_experiments.sql
sqlite3 results.db < sql/schema/02_metrics.sql
sqlite3 results.db < sql/schema/03_attacks.sql
sqlite3 results.db < sql/schema/04_indexes.sql
