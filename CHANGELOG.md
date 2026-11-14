# Changelog

## 0.1.12

- **Partition parent fan-out:** `tci.create_partitioned` /
  `create_filtered_partitioned`, `count_at_partitioned` /
  `count_at_filtered_partitioned`, `maintain_partitioned` /
  `maintain_filters_partitioned`, `list_partition_leaves`. No packed index on
  the parent; missing leaf indexes → ERROR (no silent undercount).
- **RLS-safe counts:** `tci.count_at_safe` / `count_at_filtered_safe` run
  INVOKER native coverage when packed path would refuse; packed `count_at*`
  still fail closed. Error text points at `*_safe`.
- **Correctness harness:** `benchmark/correctness_stress.sql` (evidence, not a
  formal proof).
- Regress: `partition_parent`, `rls_safe`. Still external preview / not GA.

## 0.1.11

- **Partition leaves allowed:** `tci.create` / `create_filtered` work on heap
  partition children (`relkind=r`, `relispartition`). **Partitioned parents**
  (`relkind=p`) still rejected — index each leaf; no cross-partition aggregate.
- Regress: `test/sql/partition_leaf.sql`. Docs/limitations/fit filter updated.
- Still external preview / not production GA.

## 0.1.10

- **Bgworker multi-DB:** `pg_tci.maintenance_databases` (comma-separated; one
  worker per DB). Each pass runs unfiltered `tci.maintain` and
  `tci.maintain_filters`. Single-DB `maintenance_database` still supported.
- **`tci.list_invalid` / `tci.rebuild_invalid`:** post-restore / invalidate bulk
  helpers; `examples/post_restore_rebuild.sh` prefers them.
- **`maintain_filters`:** relinks filtered catalog rows before seal/compact
  (OID drift after restore).
- **`tci.filter_fit_estimate`:** cardinality hint from `pg_stats` (not a
  latency guarantee).
- **`tci.health` detail:** richer write-amp / capacity / invalid hints.
- Docs: operations write-amp section. Regress: `test/sql/ops010.sql`.
- Still **external preview** / not production GA.

## 0.1.9

- **Packaging (docs/scripts, no API change):** examples microbench /
  `post_restore_rebuild`, `make_release_tarball`; `maintain_cron.sh` runs
  `maintain_filters`. CI: installcheck, Linux tarball artifact; tag release.
- **Native filtered TCI:** `tci.create_filtered` / `count_at_filtered` — partial
  Packed IAR instances for single-column equality filters (no slice tables / no
  row copies). Reuses TCIP v1, MVCC tail, seal/compact, shard routing.
- Type-safe filter values (text/varchar/int/bigint/enum); explicit NULL semantics;
  unregistered filters ERROR (never silent wrong index).
- `maintain_filters`, `seal_filtered` (batch-ID exact-once), `list_filters`,
  rebuild/drop/invalidate filtered variants.
- **Hardening:** RLS fail-closed on COUNT (aggregates must not bypass row
  policies); reject partitioned sources; dump/restore OID relink with
  invalidation + native fallback until `rebuild_filtered`; `tci.storage_bytes`.
- Unfiltered `tci.count_at` / `tci.create` semantics unchanged (plus RLS check).
- Regression: `test/sql/filtered.sql`.

## 0.1.8

- **Privilege hardening:** revoke `PUBLIC` EXECUTE on admin DEFINER APIs;
  `tci.create` grants admin EXECUTE to the table owner; `tci.grant_admin` /
  `tci.revoke_admin` for DBAs
- **Optional maintenance bgworker** via `shared_preload_libraries='pg_tci'` and
  `pg_tci.enable_maintenance_worker=on` (GUCs: naptime, tail_target, database, …)
- **Monitoring:** `tci.health`, `tci.maint_history`
- **Tests:** expanded privileges + `mvcc` REPEATABLE READ / fail-closed regress
- **Isolation:** `count_rr_insert`, `seal_during_rr` (pg_isolation_regress)
- Still not a formal MVCC proof; high-concurrency latency spikes remain a known limit

## 0.1.7-preview

- Fused set-based run prefix aggregation for `tci.count_at` (`runs_prefix_sum`)
- Generation-scoped `tail_sum_gen` on the hot path
- Documentation / repository finalization for external preview

## 0.1.6-preview

- Seal pipeline / PK-oriented DELETE improvements (see upgrade script)

## 0.1.5-preview

- Run budget / `compact_budget` and related maintenance controls

## 0.1.4-preview

- Sharded sealing foundations; rebuild/seal advisory lock ordering

## 0.1.3-preview

- Bounded seal / maintain orchestration expansions

## 0.1.2-preview – 0.1.0-preview

- Initial packed IAR + MVCC tail preview packaging, TCIP v1 C decoder,
  privileges, dump/restore hooks, and progressive maintenance API

Upgrade between packaged versions via sequential `sql/pg_tci--A--B.sql` scripts.
