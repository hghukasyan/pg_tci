# Limitations — pg_tci 0.1.12

- **Not a formal MVCC proof.** Packaged `mvcc` regress covers same-snapshot
  REPEATABLE READ exactness and invalidate fail-closed; SERIALIZABLE + seal
  under high contention is only lightly covered.
- **Not an Index AM.** No planner integration; callers must use `tci.count_at`
  / `tci.count_at_filtered`.
- **Single start/end `timestamptz` pair** per source table.
- **Filtered coverage** is equality on one registered column only (plus
  `IS NULL`). No arbitrary `WHERE`, expressions, or JOINs. Practical win is
  typically ≤16–32 registered values; at ≥64–256 highly selective keys, native
  btree COUNT may be faster (see `benchmark/results/tci_filtered_native.md`).
  Use `tci.filter_fit_estimate(source, filter_col)` for a **hint** only — always
  microbench.
- **Partitioned parents** have no packed index on the parent. Use
  `tci.create_partitioned` / `count_at_partitioned` to fan out across **leaves**
  (0.1.12). Re-run after ATTACH. Missing leaf indexes → ERROR.
- **RLS:** packed `count_at*` refuse when policies would be bypassed; use
  `tci.count_at_safe` / `count_at_filtered_safe` for native coverage under
  session policies.
- **Dump/restore:** catalog rows are dumped; after restore, OID relink
  invalidates until `rebuild` / `rebuild_filtered` / `rebuild_invalid` (COUNT
  uses exact native fallback meanwhile).
- **No** automatic optimization of arbitrary `SELECT COUNT(*)`, JOINs, general
  filtered aggregates, weighted intervals, or multi-column search.
- **Not production GA** — external preview only.
- **Maintenance:** optional bgworker via `shared_preload_libraries` — one worker
  per entry in `pg_tci.maintenance_databases` (or single `maintenance_database`);
  each pass runs unfiltered `maintain` + `maintain_filters`. External cron still
  supported (`examples/maintain_cron.sh`).
- **Write amplification:** every source DML emits TCI tail deltas; seal/compact
  must keep up or `count_at*` latency grows. See operations capacity section.
- **SECURITY DEFINER:** admin EXECUTE is revoked from PUBLIC; owners get grants
  from `tci.create` / `tci.grant_admin`. Review before multi-tenant production.
- Under **high concurrency** (e.g. 50 readers + heavy writes), maintenance and
  resource contention can dominate latency despite packed runs.
- **v21:** adaptive routing to native COUNT was rejected (no stable crossover).
