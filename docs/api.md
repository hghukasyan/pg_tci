# Public API — pg_tci 0.1.12

Installed signatures (PostgreSQL 18, `CREATE EXTENSION pg_tci` → 0.1.12):

Privilege checks use **`session_user`** inside `SECURITY DEFINER` bodies.
Admin functions also require **EXECUTE** (revoked from PUBLIC in 0.1.8;
granted to table owner by `tci.create`, or via `tci.grant_admin`).

| Privilege class | Requirement |
|-----------------|-------------|
| Read APIs | `SELECT` on source table (+ PUBLIC EXECUTE) |
| Admin APIs | EXECUTE + table owner **or** `TRIGGER` |

Schema `tci_internal` is revoked from `PUBLIC`.

## Functions

```text
tci.create(
  source_table regclass,
  start_col name,
  end_col name,
  chunk_bytes integer DEFAULT 8192,
  cp_interval integer DEFAULT 64,       -- 32|64|128
  id_col name DEFAULT 'id',
  shard_count integer DEFAULT 1         -- 1..64
) → integer                             -- index_id

tci.count_at(source_table regclass, ts timestamptz) → bigint

tci.create_filtered(
  source_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,              -- NULL ⇒ match IS NULL
  chunk_bytes int DEFAULT 8192,
  cp_interval int DEFAULT 64,
  id_col name DEFAULT 'id',
  shard_count int DEFAULT 1
) → integer

tci.count_at_filtered(
  source_table regclass,
  as_of timestamptz,
  filter_column name,
  filter_value text
) → bigint                        -- ERROR if filter not registered

tci.list_filters(source_table) → TABLE(...)
tci.maintain_filters(source_table, tail_target int DEFAULT 16384,
                     max_live_runs int DEFAULT 8)
tci.rebuild_filtered / drop_filtered / invalidate_filtered /
  seal_filtered / compact_filtered  -- admin; filter_column + filter_value
tci.storage_bytes(source_table) → TABLE(component, index_id, filter_col,
                                        filter_value, bytes)

tci.stats(source_table regclass) → TABLE(
  index_id, published, valid, generation, live_runs, retired_runs,
  n_chunks, n_tail, chunk_bytes, cp_interval, chunks_bytes, notes)

tci.shard_stats(source_table regclass) → TABLE(
  shard_id, n_tail, live_runs, n_entries)

tci.seal(source_table regclass) → bigint

tci.seal_bounded(
  source_table regclass,
  max_rows integer DEFAULT 8192,
  p_shard_id integer DEFAULT NULL,
  min_rows integer DEFAULT NULL
) → bigint

tci.compact(source_table regclass) → bigint

tci.compact_pairwise(
  source_table regclass,
  p_shard_id integer DEFAULT NULL
) → bigint

tci.compact_budget(
  source_table regclass,
  p_shard_id integer DEFAULT NULL,
  max_live_runs integer DEFAULT 16,
  fan_in integer DEFAULT 4,
  max_input_entries integer DEFAULT 250000
) → bigint

tci.maintain(
  source_table regclass,
  tail_target integer DEFAULT 16384,
  max_live_runs integer DEFAULT 8,
  budget_ms integer DEFAULT 2000,
  max_active_writers integer DEFAULT 4,
  max_seal_rows integer DEFAULT 8192,
  do_compact boolean DEFAULT true,
  compact_mode text DEFAULT 'pairwise'
) → TABLE(sealed, compacted, seal_run_id, compact_run_id,
          n_tail_before, n_live_before, n_tail_after, n_live_after,
          seal_ms, compact_ms, skipped_reason, writer_activity, lock_acquired)

tci.invalidate(source_table regclass) → void
tci.rebuild(source_table regclass) → void

tci.capacity(source_table regclass) → TABLE(... seal/ingest/compact counters ...)
tci.capacity_reset(source_table regclass) → void

tci.health(source_table regclass) → TABLE(
  index_id, source_table_name, published, valid, shard_count, generation,
  n_tail, live_runs, deltas_sealed, deltas_sealed_per_sec,
  deltas_ingested, deltas_ingested_per_sec, last_seal_at,
  seconds_since_reset, capacity_ok, detail)

tci.maint_history(source_table regclass, max_rows integer DEFAULT 20)
  → TABLE(id, op, started_at, duration_ms, n_tail_before, n_tail_after,
          n_live_before, n_live_after, skipped_reason, detail)

tci.grant_admin(target_role name) → void   -- superuser / db owner
tci.revoke_admin(target_role name) → void

tci.set_shard_count(source_table regclass, new_count integer) → void

tci.list_invalid(source_table regclass DEFAULT NULL)
  → TABLE(index_id, source_table_name, filter_col, filter_value, filter_is_null,
          published, valid, notes)

tci.rebuild_invalid(source_table regclass DEFAULT NULL)  -- admin
  → TABLE(index_id, source_table_name, filter_col, filter_value, action)

tci.filter_fit_estimate(source_table regclass, filter_column name)
  → TABLE(filter_col, n_distinct_estimate, registered_filters, hint, detail)
  -- hint: likely_ok | measure_required | native_may_win (not a latency guarantee)

tci.list_partition_leaves(parent) → TABLE(leaf, has_unfiltered, n_filters)
tci.create_partitioned(parent, start, end, ...) → TABLE(leaf, index_id, action)
tci.create_filtered_partitioned(parent, ..., filter_col, filter_value, ...)
tci.count_at_partitioned(parent, ts) → bigint
tci.count_at_filtered_partitioned(parent, ts, filter_col, filter_value) → bigint
tci.maintain_partitioned / maintain_filters_partitioned(...)
tci.count_at_safe / count_at_filtered_safe(...)
  -- INVOKER native under RLS when packed would refuse; else packed
```

### GUCs (optional bgworker)

```text
pg_tci.enable_maintenance_worker   # PGC_POSTMASTER, default off; needs shared_preload
pg_tci.maintenance_databases       # PGC_POSTMASTER, comma-separated DBs (one worker each)
pg_tci.maintenance_database        # PGC_POSTMASTER, used if databases empty; empty → postgres
pg_tci.maintenance_naptime         # PGC_SIGHUP, seconds, default 60
pg_tci.maintenance_tail_target     # PGC_SIGHUP, default 16384
pg_tci.maintenance_max_live_runs   # PGC_SIGHUP, default 8
pg_tci.maintenance_max_seal_rows   # PGC_SIGHUP, default 8192
```


## Error / fail-closed behavior

- Corrupted TCIP chunks → ERROR
- Missing / renamed source after restore → error or invalidation via `relink_source`
  / `relink_filtered` (filtered COUNT falls back to native until rebuild)
- Invalid / unpublished index → native `COUNT` (not stale packed values)
- Unregistered filter → ERROR (never silent wrong index)
- RLS enabled without bypass → ERROR on `count_at` / `count_at_filtered`
- Partitioned **parent** → ERROR on create; partition **leaves** allowed

## Snapshot guarantees

`count_at` uses the caller’s snapshot. Compare to native `COUNT` under the
**same** snapshot only.
