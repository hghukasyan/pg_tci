-- pg_tci 0.1.1 → 0.1.2-preview: low-contention bounded maintenance
COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.2-preview)';

-- ---------------------------------------------------------------------------
-- Instrumentation log (session-visible; dumped for research DBs optionally)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tci_internal.maint_log (
  id              bigserial PRIMARY KEY,
  index_id        int NOT NULL,
  op              text NOT NULL,           -- seal|compact|maintain|count_slow
  started_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  duration_ms     double precision,
  lock_wait_ms    double precision,
  n_tail_before   bigint,
  n_tail_after    bigint,
  n_live_before   int,
  n_live_after    int,
  n_rows_in       bigint,
  n_chunks_out    int,
  run_id          bigint,
  wal_bytes       bigint,
  skipped_reason  text,
  detail          text
);

SELECT pg_catalog.pg_extension_config_dump('tci_internal.maint_log', '');

REVOKE ALL ON TABLE tci_internal.maint_log FROM PUBLIC;

CREATE OR REPLACE FUNCTION tci_internal.log_maint(
  p_index_id int,
  p_op text,
  p_duration_ms double precision,
  p_lock_wait_ms double precision,
  p_n_tail_before bigint,
  p_n_tail_after bigint,
  p_n_live_before int,
  p_n_live_after int,
  p_n_rows_in bigint,
  p_n_chunks_out int,
  p_run_id bigint,
  p_wal_bytes bigint,
  p_skipped text,
  p_detail text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $L$
BEGIN
  INSERT INTO tci_internal.maint_log(
    index_id, op, duration_ms, lock_wait_ms,
    n_tail_before, n_tail_after, n_live_before, n_live_after,
    n_rows_in, n_chunks_out, run_id, wal_bytes, skipped_reason, detail)
  VALUES (
    p_index_id, p_op, p_duration_ms, p_lock_wait_ms,
    p_n_tail_before, p_n_tail_after, p_n_live_before, p_n_live_after,
    p_n_rows_in, p_n_chunks_out, p_run_id, p_wal_bytes, p_skipped, p_detail);
END;
$L$;

REVOKE ALL ON FUNCTION tci_internal.log_maint(
  int, text, double precision, double precision, bigint, bigint, int, int,
  bigint, int, bigint, bigint, text, text) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Bounded seal: seal oldest complete timestamps up to max_rows (by tail rows)
-- Leaves remaining tail intact (no SKIP LOCKED correctness holes).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.seal_bounded(
  source_table regclass,
  max_rows int DEFAULT 8192
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
  n_chunks int;
  t_lock0 timestamptz;
  t0 timestamptz := clock_timestamp();
  lock_wait_ms double precision;
  n_tail_b bigint;
  n_tail_a bigint;
  n_live_b int;
  n_live_a int;
  wal0 pg_lsn;
  wal1 pg_lsn;
  cutoff timestamptz;
  n_src bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;

  SELECT count(*) INTO n_tail_b FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;

  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  -- Bound by row LIMIT via index order (avoid full-tail GROUP BY).
  -- Take oldest max_rows, then extend to complete the last timestamp.
  IF to_regclass('pg_temp._tci_batch') IS NOT NULL THEN
    DROP TABLE _tci_batch;
  END IF;
  CREATE TEMP TABLE _tci_batch ON COMMIT DROP AS
  SELECT id, ts, delta
  FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = idx.generation
  ORDER BY ts, id
  LIMIT max_rows;

  SELECT count(*), max(ts) INTO n_src, cutoff FROM _tci_batch;
  IF cutoff IS NULL OR n_src = 0 THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      n_tail_b, n_tail_b, n_live_b, n_live_b,
      0, 0, NULL::bigint, 0, 'empty_tail', NULL);
    RETURN NULL;
  END IF;

  -- Complete the boundary timestamp (no partial-ts seal)
  INSERT INTO _tci_batch(id, ts, delta)
  SELECT t.id, t.ts, t.delta
  FROM tci_internal.tail t
  WHERE t.index_id = idx.index_id
    AND t.generation = idx.generation
    AND t.ts = cutoff
    AND NOT EXISTS (SELECT 1 FROM _tci_batch b WHERE b.id = t.id);

  SELECT count(*) INTO n_src FROM _tci_batch;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn,
         ts,
         tci_internal.ts_us(ts) AS ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT b.ts, sum(b.delta)::bigint AS delta
    FROM _tci_batch b
    GROUP BY b.ts HAVING sum(b.delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;
  IF n = 0 THEN
    -- all deltas cancelled in batch; still delete the batch rows
    DELETE FROM tci_internal.tail t
    USING _tci_batch b
    WHERE t.id = b.id;
    SELECT count(*) INTO n_tail_a FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      n_tail_b, n_tail_a, n_live_b, n_live_b,
      n_src, 0, NULL::bigint,
      pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint::bigint,
      'cancelled_batch', format('cutoff=%s', cutoff));
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  SELECT count(*)::int INTO n_chunks
  FROM tci_internal.chunks WHERE index_id = idx.index_id AND run_id = rid;

  DELETE FROM tci_internal.tail t
  USING _tci_batch b
  WHERE t.id = b.id;

  SELECT count(*) INTO n_tail_a FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  wal1 := pg_current_wal_lsn();

  PERFORM tci_internal.log_maint(
    idx.index_id, 'seal_bounded',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    n_tail_b, n_tail_a, n_live_b, n_live_a,
    n, n_chunks, rid, pg_wal_lsn_diff(wal1, wal0)::bigint,
    NULL, format('cutoff=%s max_rows=%s', cutoff, max_rows));

  RETURN rid;
END;
$$;

-- Keep full seal for rebuild/admin; instrument it lightly
CREATE OR REPLACE FUNCTION tci.seal(source_table regclass)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
  t0 timestamptz := clock_timestamp();
  t_lock0 timestamptz;
  lock_wait_ms double precision;
  n_tail_b bigint;
  wal0 pg_lsn;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  SELECT count(*) INTO n_tail_b FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn,
         ts,
         tci_internal.ts_us(ts) AS ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT t.ts, sum(t.delta)::bigint AS delta
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation
    GROUP BY t.ts HAVING sum(t.delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;
  IF n = 0 THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      n_tail_b, n_tail_b, NULL::int, NULL::int, 0, 0, NULL::bigint, 0, 'empty_tail', 'full');
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  DELETE FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = idx.generation;

  PERFORM tci_internal.log_maint(
    idx.index_id, 'seal',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    n_tail_b, 0, NULL::int, NULL::int, n, NULL::int, rid,
    pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint, NULL, 'full');

  RETURN rid;
END;
$$;

-- ---------------------------------------------------------------------------
-- Pairwise compact: merge two oldest live runs only
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.compact_pairwise(source_table regclass)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  ids bigint[];
  rid bigint;
  n int;
  c RECORD;
  t0 timestamptz := clock_timestamp();
  t_lock0 timestamptz;
  lock_wait_ms double precision;
  n_live_b int;
  n_live_a int;
  n_chunks_in int;
  wal0 pg_lsn;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  SELECT array_agg(run_id ORDER BY run_id) INTO ids
  FROM (
    SELECT run_id FROM tci_internal.runs
    WHERE index_id = idx.index_id AND status = 'live'
    ORDER BY run_id
    LIMIT 2
  ) s;

  IF ids IS NULL OR array_length(ids, 1) < 2 THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_pairwise',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0, 'lt_2_runs', NULL);
    RETURN NULL;
  END IF;

  SELECT count(*)::int INTO n_chunks_in
  FROM tci_internal.chunks
  WHERE index_id = idx.index_id AND run_id = ANY (ids);

  IF to_regclass('pg_temp._tci_raw') IS NOT NULL THEN
    DROP TABLE _tci_raw;
  END IF;
  CREATE TEMP TABLE _tci_raw (ts timestamptz, delta smallint) ON COMMIT DROP;
  FOR c IN
    SELECT payload FROM tci_internal.chunks
    WHERE index_id = idx.index_id AND run_id = ANY (ids)
    ORDER BY run_id, chunk_id
  LOOP
    INSERT INTO _tci_raw(ts, delta)
    SELECT timestamptz '2000-01-01 00:00:00+00' + (u.ts_us * interval '1 microsecond'),
           u.delta
    FROM tci_internal.unpack_entries(c.payload) AS u;
  END LOOP;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn,
         ts,
         tci_internal.ts_us(ts) AS ts_us,
         delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT ts, sum(delta)::bigint AS delta FROM _tci_raw
    GROUP BY ts HAVING sum(delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  UPDATE tci_internal.runs SET status = 'retired'
   WHERE index_id = idx.index_id AND run_id = ANY (ids);
  DELETE FROM tci_internal.chunks
   WHERE index_id = idx.index_id AND run_id = ANY (ids);

  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  PERFORM tci_internal.log_maint(
    idx.index_id, 'compact_pairwise',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    NULL, NULL, n_live_b, n_live_a, n, n_chunks_in, rid,
    pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint,
    NULL, format('merged=%s', ids));

  RETURN rid;
END;
$$;

-- ---------------------------------------------------------------------------
-- maintain: seal-bounded by default; optional compact; one primary action
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS tci.maintain(regclass, int, int, int, int);

CREATE OR REPLACE FUNCTION tci.maintain(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8,
  budget_ms int DEFAULT 2000,
  max_active_writers int DEFAULT 64,
  max_seal_rows int DEFAULT 8192,
  do_compact boolean DEFAULT true,
  compact_mode text DEFAULT 'pairwise'  -- pairwise | all
)
RETURNS TABLE(
  sealed boolean,
  compacted boolean,
  seal_run_id bigint,
  compact_run_id bigint,
  n_tail_before bigint,
  n_live_before int,
  n_tail_after bigint,
  n_live_after int,
  seal_ms double precision,
  compact_ms double precision,
  skipped_reason text,
  writer_activity int,
  lock_acquired boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  t0 timestamptz := clock_timestamp();
  t1 timestamptz;
  elapsed_ms double precision := 0;
  n_writers int := 0;
  lock_key1 int := 88442201;
  lock_key2 int;
  did_seal boolean := false;
  did_compact boolean := false;
  s_rid bigint := NULL;
  c_rid bigint := NULL;
  s_ms double precision := NULL;
  c_ms double precision := NULL;
  skip text := NULL;
  got_lock boolean := false;
  n_tail bigint;
  n_live int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF NOT idx.valid OR NOT idx.published THEN
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    n_tail_before := 0; n_live_before := 0;
    n_tail_after := 0; n_live_after := 0;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := 'invalid_or_unpublished';
    writer_activity := 0; lock_acquired := false;
    RETURN NEXT; RETURN;
  END IF;

  IF tail_target < 1 OR max_live_runs < 2 OR budget_ms < 1 OR max_seal_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: invalid maintain thresholds';
  END IF;
  IF compact_mode NOT IN ('pairwise', 'all') THEN
    RAISE EXCEPTION 'pg_tci: compact_mode must be pairwise|all';
  END IF;

  lock_key2 := idx.index_id;
  got_lock := pg_try_advisory_xact_lock(lock_key1, lock_key2);
  IF NOT got_lock THEN
    SELECT count(*) INTO n_tail FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
    SELECT count(*)::int INTO n_live FROM tci_internal.runs
     WHERE index_id = idx.index_id AND status = 'live';
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    n_tail_before := n_tail; n_live_before := n_live;
    n_tail_after := n_tail; n_live_after := n_live;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := 'advisory_lock_busy';
    writer_activity := 0; lock_acquired := false;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'maintain', 0, 0, n_tail, n_tail, n_live, n_live,
      0, 0, NULL::bigint, 0, 'advisory_lock_busy', NULL);
    RETURN NEXT; RETURN;
  END IF;

  SELECT count(*)::int INTO n_writers
  FROM pg_stat_activity a
  WHERE a.pid <> pg_backend_pid()
    AND a.datid = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND a.state = 'active'
    AND a.wait_event_type IS DISTINCT FROM 'Client'
    AND (a.query ILIKE '%INSERT%INTO%sessions%'
         OR a.query ILIKE '%UPDATE%sessions%'
         OR a.query ILIKE '%DELETE%FROM%sessions%');

  SELECT count(*) INTO n_tail FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  n_tail_before := n_tail;
  n_live_before := n_live;

  -- Backpressure: if tail is critically large, seal anyway despite writers.
  IF n_writers > max_active_writers AND n_tail < (tail_target::bigint * 4) THEN
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    n_tail_after := n_tail; n_live_after := n_live;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := format('writer_activity=%s', n_writers);
    writer_activity := n_writers; lock_acquired := true;
    RETURN NEXT; RETURN;
  END IF;

  -- Prefer sealing a bounded batch when tail is large (keeps txn short)
  IF n_tail >= tail_target THEN
    t1 := clock_timestamp();
    s_rid := tci.seal_bounded(source_table, max_seal_rows);
    s_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_seal := true;  -- attempted; rid may be null if cancelled batch
    elapsed_ms := (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8;
  END IF;

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  -- Compact in same txn only if requested AND budget remains AND seal not huge
  IF do_compact AND n_live > max_live_runs AND elapsed_ms < budget_ms THEN
    t1 := clock_timestamp();
    IF compact_mode = 'pairwise' THEN
      c_rid := tci.compact_pairwise(source_table);
    ELSE
      c_rid := tci.compact(source_table);
    END IF;
    c_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_compact := c_rid IS NOT NULL;
  ELSIF do_compact AND n_live > max_live_runs THEN
    skip := 'budget_exhausted_before_compact';
  END IF;

  SELECT count(*) INTO n_tail FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  IF skip IS NULL AND NOT did_seal AND NOT did_compact THEN
    skip := 'below_thresholds';
  END IF;

  sealed := did_seal AND s_rid IS NOT NULL;
  compacted := did_compact;
  seal_run_id := s_rid;
  compact_run_id := c_rid;
  n_tail_after := n_tail;
  n_live_after := n_live;
  seal_ms := s_ms;
  compact_ms := c_ms;
  skipped_reason := skip;
  writer_activity := n_writers;
  lock_acquired := true;

  PERFORM tci_internal.log_maint(
    idx.index_id, 'maintain',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, NULL,
    n_tail_before, n_tail, n_live_before, n_live,
    NULL, NULL, COALESCE(s_rid, c_rid), NULL, skip,
    format('seal=%s compact=%s mode=%s', did_seal, did_compact, compact_mode));

  RETURN NEXT;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.maintain(regclass, int, int, int, int, int, boolean, text) TO PUBLIC;
