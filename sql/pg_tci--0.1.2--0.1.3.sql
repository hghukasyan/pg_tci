-- pg_tci 0.1.2 -> 0.1.3 — low-contention seal (decouple ingest from metadata FOR UPDATE)
-- Architectural change: writers use FOR KEY SHARE; seal/compact use advisory locks
-- only (no indexes FOR UPDATE). Rebuild keeps FOR UPDATE for generation safety.

ALTER TABLE tci_internal.maint_log
  ADD COLUMN IF NOT EXISTS lock_hold_ms double precision;

CREATE TABLE IF NOT EXISTS tci_internal.cap_counters (
  index_id          int PRIMARY KEY REFERENCES tci_internal.indexes ON DELETE CASCADE,
  deltas_sealed     bigint NOT NULL DEFAULT 0,
  seal_txns         bigint NOT NULL DEFAULT 0,
  seal_ms_sum       double precision NOT NULL DEFAULT 0,
  compact_txns      bigint NOT NULL DEFAULT 0,
  compact_bytes     bigint NOT NULL DEFAULT 0,
  compact_ms_sum    double precision NOT NULL DEFAULT 0,
  last_seal_at      timestamptz,
  last_compact_at   timestamptz,
  reset_at          timestamptz NOT NULL DEFAULT clock_timestamp()
);

SELECT pg_catalog.pg_extension_config_dump('tci_internal.cap_counters', '');
REVOKE ALL ON TABLE tci_internal.cap_counters FROM PUBLIC;

CREATE OR REPLACE FUNCTION tci_internal.ensure_cap(p_index_id int)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  INSERT INTO tci_internal.cap_counters(index_id) VALUES (p_index_id)
  ON CONFLICT (index_id) DO NOTHING;
$$;

CREATE OR REPLACE FUNCTION tci_internal.note_seal(
  p_index_id int, p_rows bigint, p_ms double precision
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.ensure_cap(p_index_id);
  UPDATE tci_internal.cap_counters
     SET deltas_sealed = deltas_sealed + coalesce(p_rows, 0),
         seal_txns = seal_txns + 1,
         seal_ms_sum = seal_ms_sum + coalesce(p_ms, 0),
         last_seal_at = clock_timestamp()
   WHERE index_id = p_index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.note_compact(
  p_index_id int, p_bytes bigint, p_ms double precision
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.ensure_cap(p_index_id);
  UPDATE tci_internal.cap_counters
     SET compact_txns = compact_txns + 1,
         compact_bytes = compact_bytes + coalesce(p_bytes, 0),
         compact_ms_sum = compact_ms_sum + coalesce(p_ms, 0),
         last_compact_at = clock_timestamp()
   WHERE index_id = p_index_id;
END;
$$;

-- Magic keys shared by maintain / seal / compact (per index_id)
CREATE OR REPLACE FUNCTION tci_internal.maint_lock_key1()
RETURNS int LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT 872014001 $$;

CREATE OR REPLACE FUNCTION tci_internal.tail_at_least(
  p_index_id int, p_generation bigint, p_n bigint
) RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT CASE
    WHEN p_n <= 1 THEN EXISTS (
      SELECT 1 FROM tci_internal.tail
      WHERE index_id = p_index_id AND generation = p_generation LIMIT 1)
    ELSE EXISTS (
      SELECT 1 FROM tci_internal.tail
      WHERE index_id = p_index_id AND generation = p_generation
      OFFSET (p_n - 1) LIMIT 1)
  END;
$$;

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
  p_detail text DEFAULT NULL,
  p_lock_hold_ms double precision DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $L$
BEGIN
  INSERT INTO tci_internal.maint_log(
    index_id, op, duration_ms, lock_wait_ms, lock_hold_ms,
    n_tail_before, n_tail_after, n_live_before, n_live_after,
    n_rows_in, n_chunks_out, run_id, wal_bytes, skipped_reason, detail)
  VALUES (
    p_index_id, p_op, p_duration_ms, p_lock_wait_ms, p_lock_hold_ms,
    p_n_tail_before, p_n_tail_after, p_n_live_before, p_n_live_after,
    p_n_rows_in, p_n_chunks_out, p_run_id, p_wal_bytes, p_skipped, p_detail);
END;
$L$;

-- ---------------------------------------------------------------------------
-- Write path: FOR KEY SHARE (not FOR SHARE)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.source_trig()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  start_old timestamptz;
  end_old timestamptz;
  start_new timestamptz;
  end_new timestamptz;
BEGIN
  -- KEY SHARE blocks rebuild FOR UPDATE; compatible with seal advisory path
  -- (seal no longer takes indexes FOR UPDATE).
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID
  FOR KEY SHARE;

  IF NOT FOUND OR NOT idx.published OR NOT idx.valid THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF TG_OP = 'INSERT' THEN
    EXECUTE format('SELECT ($1).%I, ($1).%I', idx.start_col, idx.end_col)
      INTO start_new, end_new USING NEW;
    INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
    VALUES (idx.index_id, idx.generation, start_new, 1);
    IF end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
      VALUES (idx.index_id, idx.generation, end_new, -1);
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('SELECT ($1).%I, ($1).%I', idx.start_col, idx.end_col)
      INTO start_old, end_old USING OLD;
    INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
    VALUES (idx.index_id, idx.generation, start_old, -1);
    IF end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
      VALUES (idx.index_id, idx.generation, end_old, 1);
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    EXECUTE format('SELECT ($1).%I, ($1).%I', idx.start_col, idx.end_col)
      INTO start_old, end_old USING OLD;
    EXECUTE format('SELECT ($1).%I, ($1).%I', idx.start_col, idx.end_col)
      INTO start_new, end_new USING NEW;
    INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
    VALUES (idx.index_id, idx.generation, start_old, -1);
    IF end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
      VALUES (idx.index_id, idx.generation, end_old, 1);
    END IF;
    INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
    VALUES (idx.index_id, idx.generation, start_new, 1);
    IF end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, ts, delta)
      VALUES (idx.index_id, idx.generation, end_new, -1);
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- seal_bounded: advisory exclusivity; no indexes FOR UPDATE
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
  t_hold0 timestamptz;
  t0 timestamptz := clock_timestamp();
  lock_wait_ms double precision;
  lock_hold_ms double precision;
  n_live_b int;
  n_live_a int;
  wal0 pg_lsn;
  wal1 pg_lsn;
  cutoff timestamptz;
  n_src bigint;
  got_lock boolean;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;

  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  -- Sealer mutual exclusion WITHOUT indexes FOR UPDATE (writers use KEY SHARE /
  -- FK KeyShare which conflict with FOR UPDATE and were the v10 serialization).
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), idx.index_id);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      0, 0, NULL::bigint, 0, 'advisory_lock_busy', NULL, 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();

  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

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
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      0, 0, NULL::bigint, 0, 'empty_tail', NULL, lock_hold_ms);
    RETURN NULL;
  END IF;

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
    DELETE FROM tci_internal.tail t
    USING _tci_batch b
    WHERE t.id = b.id;
    PERFORM tci_internal.note_seal(idx.index_id, n_src,
      EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      n_src, 0, NULL::bigint,
      pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint,
      'cancelled_batch', format('cutoff=%s', cutoff), lock_hold_ms);
    RETURN NULL;
  END IF;

  -- Atomic publication in this same transaction (exact-once under MVCC).
  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  SELECT count(*)::int INTO n_chunks
  FROM tci_internal.chunks WHERE index_id = idx.index_id AND run_id = rid;

  DELETE FROM tci_internal.tail t
  USING _tci_batch b
  WHERE t.id = b.id;

  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  wal1 := pg_current_wal_lsn();
  lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;

  PERFORM tci_internal.note_seal(idx.index_id, n_src,
    EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);

  PERFORM tci_internal.log_maint(
    idx.index_id, 'seal_bounded',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    NULL, NULL, n_live_b, n_live_a,
    n_src, n_chunks, rid, pg_wal_lsn_diff(wal1, wal0)::bigint,
    NULL, format('cutoff=%s max_rows=%s no_meta_for_update=1', cutoff, max_rows),
    lock_hold_ms);

  RETURN rid;
END;
$$;

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
  t_hold0 timestamptz;
  lock_wait_ms double precision;
  lock_hold_ms double precision;
  n_src bigint;
  wal0 pg_lsn;
  got_lock boolean;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), idx.index_id);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, NULL::int, NULL::int, 0, 0, NULL::bigint, 0,
      'advisory_lock_busy', 'full', 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();
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
    SELECT count(*) INTO n_src FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
    DELETE FROM tci_internal.tail
    WHERE index_id = idx.index_id AND generation = idx.generation;
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      n_src, 0, NULL::int, NULL::int, 0, 0, NULL::bigint, 0, 'empty_tail', 'full',
      lock_hold_ms);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  SELECT count(*) INTO n_src FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  DELETE FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = idx.generation;

  lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
  PERFORM tci_internal.note_seal(idx.index_id, n_src,
    EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
  PERFORM tci_internal.log_maint(
    idx.index_id, 'seal',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    n_src, 0, NULL::int, NULL::int, n, NULL::int, rid,
    pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint, NULL, 'full', lock_hold_ms);

  RETURN rid;
END;
$$;

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
  t_hold0 timestamptz;
  lock_wait_ms double precision;
  lock_hold_ms double precision;
  n_live_b int;
  n_live_a int;
  n_chunks_in int;
  wal0 pg_lsn;
  got_lock boolean;
  bytes_in bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), idx.index_id);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_pairwise',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0,
      'advisory_lock_busy', NULL, 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();
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
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_pairwise',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0, 'lt_2_runs', NULL,
      lock_hold_ms);
    RETURN NULL;
  END IF;

  SELECT count(*)::int, coalesce(sum(octet_length(payload)),0)::bigint
    INTO n_chunks_in, bytes_in
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
  lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;

  PERFORM tci_internal.note_compact(idx.index_id, bytes_in,
    EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);

  PERFORM tci_internal.log_maint(
    idx.index_id, 'compact_pairwise',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    NULL, NULL, n_live_b, n_live_a, n, n_chunks_in, rid,
    pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint,
    NULL, format('merged=%s', ids), lock_hold_ms);

  RETURN rid;
END;
$$;

-- compact (merge-all) and rebuild: rebuild keeps FOR UPDATE for generation bump
CREATE OR REPLACE FUNCTION tci.compact(source_table regclass)
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
  got_lock boolean;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), idx.index_id);
  IF NOT got_lock THEN
    RETURN NULL;
  END IF;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  SELECT array_agg(run_id) INTO ids
  FROM tci_internal.runs
  WHERE index_id = idx.index_id AND status = 'live';

  IF ids IS NULL OR array_length(ids, 1) < 2 THEN
    RETURN NULL;
  END IF;

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

  RETURN rid;
END;
$$;

-- maintain: cheap threshold probe; seal already takes advisory
CREATE OR REPLACE FUNCTION tci.maintain(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8,
  budget_ms int DEFAULT 2000,
  max_active_writers int DEFAULT 4,
  max_seal_rows int DEFAULT 8192,
  do_compact boolean DEFAULT true,
  compact_mode text DEFAULT 'pairwise'
) RETURNS TABLE (
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
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  lock_key1 int := tci_internal.maint_lock_key1();
  lock_key2 int;
  got_lock boolean;
  n_writers int;
  t_seal0 timestamptz;
  t_comp0 timestamptz;
  s_rid bigint;
  c_rid bigint;
  n_tail bigint;
  n_live int;
  need_seal boolean;
  need_backpressure boolean;
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
    SELECT count(*)::int INTO n_live FROM tci_internal.runs
     WHERE index_id = idx.index_id AND status = 'live';
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    n_tail_before := NULL; n_live_before := n_live;
    n_tail_after := NULL; n_live_after := n_live;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := 'advisory_lock_busy';
    writer_activity := 0; lock_acquired := false;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'maintain', 0, 0, NULL, NULL, n_live, n_live,
      0, 0, NULL::bigint, 0, 'advisory_lock_busy', NULL, 0);
    RETURN NEXT; RETURN;
  END IF;

  SELECT count(*)::int INTO n_writers
  FROM pg_stat_activity a
  WHERE a.pid <> pg_backend_pid()
    AND a.datid = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND a.state IN ('active', 'idle in transaction');

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  need_seal := tci_internal.tail_at_least(idx.index_id, idx.generation, tail_target);
  need_backpressure := tci_internal.tail_at_least(
    idx.index_id, idx.generation, (tail_target::bigint * 4));

  IF need_seal THEN
    n_tail := tail_target; -- lower-bound marker; avoid full-tail count on hot path
  ELSE
    SELECT count(*) INTO n_tail FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
  END IF;
  n_tail_before := n_tail;
  n_live_before := n_live;
  writer_activity := n_writers;
  lock_acquired := true;
  sealed := false; compacted := false;
  seal_run_id := NULL; compact_run_id := NULL;
  seal_ms := NULL; compact_ms := NULL;
  skipped_reason := NULL;

  -- Defer seal while writers are hot unless tail is critically large.
  IF n_writers > max_active_writers AND NOT need_backpressure THEN
    skipped_reason := 'writer_activity';
    n_tail_after := n_tail; n_live_after := n_live;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'maintain', 0, 0, n_tail, n_tail, n_live, n_live,
      0, 0, NULL::bigint, 0, 'writer_activity', NULL, 0);
    RETURN NEXT; RETURN;
  END IF;

  IF need_seal OR need_backpressure THEN
    t_seal0 := clock_timestamp();
    -- Nested seal_bounded try-lock succeeds (same xact already holds advisory).
    s_rid := tci.seal_bounded(source_table, max_seal_rows);
    seal_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_seal0)) * 1000.0;
    sealed := s_rid IS NOT NULL;
    seal_run_id := s_rid;
  END IF;

  IF do_compact AND n_live >= max_live_runs THEN
    t_comp0 := clock_timestamp();
    IF compact_mode = 'pairwise' THEN
      c_rid := tci.compact_pairwise(source_table);
    ELSE
      c_rid := tci.compact(source_table);
    END IF;
    compact_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_comp0)) * 1000.0;
    compacted := c_rid IS NOT NULL;
    compact_run_id := c_rid;
  END IF;

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  -- Avoid full-tail count after seal when we know we drained a batch.
  IF sealed THEN
    n_tail := NULL;
  ELSE
    SELECT count(*) INTO n_tail FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
  END IF;
  n_tail_after := n_tail;
  n_live_after := n_live;

  IF NOT sealed AND NOT compacted AND skipped_reason IS NULL THEN
    skipped_reason := 'under_threshold';
  END IF;

  PERFORM tci_internal.log_maint(
    idx.index_id, 'maintain',
    coalesce(seal_ms,0) + coalesce(compact_ms,0), 0,
    n_tail_before, n_tail_after, n_live_before, n_live_after,
    NULL, NULL, coalesce(seal_run_id, compact_run_id), 0,
    skipped_reason, format('max_seal_rows=%s', max_seal_rows), NULL);

  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION tci.capacity(source_table regclass)
RETURNS TABLE (
  index_id int,
  deltas_sealed bigint,
  seal_txns bigint,
  seal_ms_sum double precision,
  deltas_sealed_per_sec double precision,
  avg_seal_ms double precision,
  compact_txns bigint,
  compact_bytes bigint,
  compact_bytes_per_sec double precision,
  seconds_since_reset double precision,
  n_tail bigint,
  live_runs int,
  last_seal_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  sec double precision;
BEGIN
  idx := tci_internal.relink_source(source_table);
  PERFORM tci_internal.ensure_cap(idx.index_id);
  RETURN QUERY
  SELECT c.index_id,
         c.deltas_sealed,
         c.seal_txns,
         c.seal_ms_sum,
         CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
              THEN (c.deltas_sealed / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
              ELSE 0::float8 END,
         CASE WHEN c.seal_txns > 0 THEN (c.seal_ms_sum / c.seal_txns)::float8 ELSE NULL END,
         c.compact_txns,
         c.compact_bytes,
         CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
              THEN (c.compact_bytes / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
              ELSE 0::float8 END,
         EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at))::float8,
         (SELECT count(*) FROM tci_internal.tail t
           WHERE t.index_id = idx.index_id AND t.generation = idx.generation),
         (SELECT count(*)::int FROM tci_internal.runs r
           WHERE r.index_id = idx.index_id AND r.status = 'live'),
         c.last_seal_at
  FROM tci_internal.cap_counters c
  WHERE c.index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.capacity_reset(source_table regclass)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  PERFORM tci_internal.ensure_cap(idx.index_id);
  UPDATE tci_internal.cap_counters
     SET deltas_sealed = 0, seal_txns = 0, seal_ms_sum = 0,
         compact_txns = 0, compact_bytes = 0, compact_ms_sum = 0,
         last_seal_at = NULL, last_compact_at = NULL,
         reset_at = clock_timestamp()
   WHERE index_id = idx.index_id;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.capacity(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity_reset(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass) TO PUBLIC;
