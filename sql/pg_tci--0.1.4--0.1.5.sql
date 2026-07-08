-- pg_tci 0.1.4 -> 0.1.5
-- - UPDATE boundary coalescing (skip unchanged endpoints; preserves exactness)
-- - Versioned shard routing (no abs(int4) overflow; frozen per index)
-- - Advisory keys: (magic+index_id, shard_id) — no cross-index collisions
-- - seal_bounded min_rows to avoid tiny-run explosion
-- - compact_budget: multi-way per-shard merge with run budget (not every seal)

ALTER TABLE tci_internal.indexes
  ADD COLUMN IF NOT EXISTS routing_version int NOT NULL DEFAULT 1
    CHECK (routing_version >= 1);

ALTER TABLE tci_internal.cap_counters
  ADD COLUMN IF NOT EXISTS deltas_ingested bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ingest_txns bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS runs_created bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS compact_merges bigint NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- Routing v1: hashtextextended → clear sign bit → mod (no abs overflow)
-- Frozen by indexes.routing_version; changing shard_count requires rebuild.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.row_shard_v1(
  p_shard_count int, p_id bigint
) RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  -- Deterministic, versioned routing. Uses md5→60-bit positive int (no abs/INT_MIN).
  -- Frozen by indexes.routing_version=1. Do not change formula without a new version.
  -- NULL id is rejected (sharded indexes require a non-NULL routing key).
  SELECT CASE
    WHEN p_id IS NULL THEN NULL
    WHEN p_shard_count <= 1 THEN 0
    ELSE mod(
      (('x' || substr(md5('tci-r1|' || p_id::text), 1, 15))::bit(60)::bigint),
      p_shard_count::bigint
    )::int
  END
$$;

CREATE OR REPLACE FUNCTION tci_internal.row_shard(
  p_shard_count int, p_id bigint
) RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT tci_internal.row_shard_v1(p_shard_count, p_id)
$$;

-- Per-index key1 space avoids index_id*64 collisions with single-shard keys.
CREATE OR REPLACE FUNCTION tci_internal.shard_lock_key1(p_index_id int)
RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT 872014010 + p_index_id
$$;

CREATE OR REPLACE FUNCTION tci_internal.shard_lock_key(
  p_index_id int, p_shard_count int, p_shard_id int
) RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  -- key2 is always shard_id (0 when unsharded); key1 namespaces by index.
  SELECT COALESCE(p_shard_id, 0)
$$;

CREATE OR REPLACE FUNCTION tci_internal.acquire_all_shard_locks(
  p_index_id int, p_shard_count int
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  s int;
  n int := GREATEST(p_shard_count, 1);
  k1 int := tci_internal.shard_lock_key1(p_index_id);
BEGIN
  FOR s IN 0..n - 1 LOOP
    PERFORM pg_advisory_xact_lock(k1, s);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.try_shard_lock(
  p_index_id int, p_shard_id int
) RETURNS boolean
LANGUAGE sql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT pg_try_advisory_xact_lock(
    tci_internal.shard_lock_key1(p_index_id),
    COALESCE(p_shard_id, 0))
$$;

CREATE OR REPLACE FUNCTION tci_internal.note_ingest(
  p_index_id int, p_deltas bigint
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.ensure_cap(p_index_id);
  UPDATE tci_internal.cap_counters
     SET deltas_ingested = deltas_ingested + coalesce(p_deltas, 0),
         ingest_txns = ingest_txns + 1
   WHERE index_id = p_index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.note_run_created(p_index_id int)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  UPDATE tci_internal.cap_counters
     SET runs_created = runs_created + 1
   WHERE index_id = p_index_id;
$$;

-- ---------------------------------------------------------------------------
-- Trigger: coalesced UPDATE + ingest counters
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
  sid int;
  id_old bigint;
  id_new bigint;
  n_delta int := 0;
BEGIN
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID
  FOR KEY SHARE;

  IF NOT FOUND OR NOT idx.published OR NOT idx.valid THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  IF TG_OP = 'INSERT' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
    IF idx.shard_count > 1 AND id_new IS NULL THEN
      RAISE EXCEPTION 'pg_tci: NULL % not allowed for sharded index', idx.id_col;
    END IF;
    sid := tci_internal.row_shard_v1(idx.shard_count, id_new);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_new, 1);
    n_delta := 1;
    IF end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_new, -1);
      n_delta := n_delta + 1;
    END IF;
    -- Ingest counters are NOT updated on the hot path (cap_counters row lock
    -- serializes writers). Estimate: ingest ≈ deltas_sealed + Δn_tail.
    RETURN NEW;

  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
    sid := tci_internal.row_shard_v1(idx.shard_count, id_old);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_old, -1);
    n_delta := 1;
    IF end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_old, 1);
      n_delta := n_delta + 1;
    END IF;
    RETURN OLD;

  ELSIF TG_OP = 'UPDATE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
    IF id_old IS DISTINCT FROM id_new THEN
      RAISE EXCEPTION 'pg_tci: primary key % change not supported (%/%)',
        idx.id_col, id_old, id_new;
    END IF;
    IF start_old IS NOT DISTINCT FROM start_new
       AND end_old IS NOT DISTINCT FROM end_new THEN
      RETURN NEW;  -- no interval change
    END IF;
    sid := tci_internal.row_shard_v1(idx.shard_count, id_old);

    -- Exact interval rewrite: undo OLD coverage, apply NEW.
    -- Skip endpoints that did not move (avoids redundant ±1 that cancel).
    IF start_old IS DISTINCT FROM start_new THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, start_old, -1);
      n_delta := n_delta + 1;
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, start_new, 1);
      n_delta := n_delta + 1;
    END IF;

    IF end_old IS DISTINCT FROM end_new THEN
      IF end_old IS NOT NULL THEN
        INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
        VALUES (idx.index_id, idx.generation, sid, end_old, 1);
        n_delta := n_delta + 1;
      END IF;
      IF end_new IS NOT NULL THEN
        INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
        VALUES (idx.index_id, idx.generation, sid, end_new, -1);
        n_delta := n_delta + 1;
      END IF;
    END IF;

    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;

-- Refuse silent shard_count change without rebuild
CREATE OR REPLACE FUNCTION tci.set_shard_count(source_table regclass, new_count int)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION
    'pg_tci: shard_count cannot change in place — call tci.rebuild after CREATE with new shard_count / re-create index';
END;
$$;

-- ---------------------------------------------------------------------------
-- seal_bounded: min_rows + new lock keys + runs_created counter
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.seal_bounded(
  source_table regclass,
  max_rows int DEFAULT 8192,
  p_shard_id int DEFAULT NULL,
  min_rows int DEFAULT NULL
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
  t_sel0 timestamptz;
  t_enc0 timestamptz;
  t_chk0 timestamptz;
  t_del0 timestamptz;
  t0 timestamptz := clock_timestamp();
  lock_wait_ms double precision;
  lock_hold_ms double precision;
  sel_ms double precision;
  enc_ms double precision;
  chk_ms double precision;
  del_ms double precision;
  n_live_b int;
  n_live_a int;
  wal0 pg_lsn;
  wal1 pg_lsn;
  cutoff timestamptz;
  n_src bigint;
  got_lock boolean;
  shard int;
  gen0 bigint;
  min_need int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;
  min_need := COALESCE(min_rows, GREATEST(max_rows / 4, 256));
  IF min_need < 1 THEN min_need := 1; END IF;
  IF min_need > max_rows THEN min_need := max_rows; END IF;

  IF idx.shard_count <= 1 THEN
    shard := 0;
  ELSE
    IF p_shard_id IS NULL OR p_shard_id < 0 OR p_shard_id >= idx.shard_count THEN
      RAISE EXCEPTION 'pg_tci: p_shard_id required in [0,% )', idx.shard_count;
    END IF;
    shard := p_shard_id;
  END IF;

  -- Cheap floor: avoid creating tiny runs when parallel sealers outrun backlog.
  IF NOT tci_internal.tail_at_least_shard(idx.index_id, idx.generation, shard, min_need) THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded', 0, 0, NULL, NULL, NULL, NULL,
      0, 0, NULL::bigint, 0, 'below_min_batch',
      format('shard=%s min_rows=%s max_rows=%s', shard, min_need, max_rows), 0);
    RETURN NULL;
  END IF;

  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard;

  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  got_lock := tci_internal.try_shard_lock(idx.index_id, shard);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0,
      'advisory_lock_busy', format('shard=%s', shard), 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();

  SELECT * INTO idx FROM tci_internal.indexes WHERE index_id = idx.index_id;
  gen0 := idx.generation;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  t_sel0 := clock_timestamp();
  IF to_regclass('pg_temp._tci_batch') IS NOT NULL THEN
    DROP TABLE _tci_batch;
  END IF;
  CREATE TEMP TABLE _tci_batch ON COMMIT DROP AS
  SELECT id, ts, delta
  FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = gen0 AND shard_id = shard
  ORDER BY ts, id
  LIMIT max_rows;
  sel_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_sel0)) * 1000.0;

  SELECT count(*), max(ts) INTO n_src, cutoff FROM _tci_batch;
  IF cutoff IS NULL OR n_src = 0 THEN
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0, 'empty_tail',
      format('shard=%s', shard), lock_hold_ms);
    RETURN NULL;
  END IF;
  IF n_src < min_need THEN
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, n_src, 0, NULL::bigint, 0, 'below_min_batch',
      format('shard=%s got=%s min=%s', shard, n_src, min_need), lock_hold_ms);
    RETURN NULL;
  END IF;

  INSERT INTO _tci_batch(id, ts, delta)
  SELECT t.id, t.ts, t.delta
  FROM tci_internal.tail t
  WHERE t.index_id = idx.index_id AND t.generation = gen0 AND t.shard_id = shard
    AND t.ts = cutoff
    AND NOT EXISTS (SELECT 1 FROM _tci_batch b WHERE b.id = t.id);
  SELECT count(*) INTO n_src FROM _tci_batch;

  t_enc0 := clock_timestamp();
  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN DROP TABLE _tci_pref; END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn, ts,
         tci_internal.ts_us(ts) AS ts_us, delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT b.ts, sum(b.delta)::bigint AS delta FROM _tci_batch b
    GROUP BY b.ts HAVING sum(b.delta) <> 0
  ) s;
  enc_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_enc0)) * 1000.0;
  SELECT count(*) INTO n FROM _tci_pref;

  IF (SELECT generation FROM tci_internal.indexes WHERE index_id = idx.index_id) <> gen0 THEN
    RAISE EXCEPTION 'pg_tci: generation changed during seal (shard=%)', shard;
  END IF;

  IF n = 0 THEN
    t_del0 := clock_timestamp();
    DELETE FROM tci_internal.tail t USING _tci_batch b WHERE t.id = b.id;
    del_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_del0)) * 1000.0;
    PERFORM tci_internal.note_seal(idx.index_id, n_src,
      EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, n_src, 0, NULL::bigint,
      pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint, 'cancelled_batch',
      format('shard=%s n_src=%s', shard, n_src), lock_hold_ms);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, shard)
  RETURNING run_id INTO rid;
  PERFORM tci_internal.note_run_created(idx.index_id);

  t_chk0 := clock_timestamp();
  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);
  chk_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_chk0)) * 1000.0;
  SELECT count(*)::int INTO n_chunks FROM tci_internal.chunks
   WHERE index_id = idx.index_id AND run_id = rid;

  t_del0 := clock_timestamp();
  DELETE FROM tci_internal.tail t USING _tci_batch b WHERE t.id = b.id;
  del_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_del0)) * 1000.0;

  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard;
  wal1 := pg_current_wal_lsn();
  lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;

  PERFORM tci_internal.note_seal(idx.index_id, n_src,
    EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
  UPDATE tci_internal.cap_counters
     SET select_ms_sum = select_ms_sum + sel_ms,
         encode_ms_sum = encode_ms_sum + enc_ms,
         chunk_ms_sum = chunk_ms_sum + chk_ms,
         delete_ms_sum = delete_ms_sum + del_ms
   WHERE index_id = idx.index_id;

  PERFORM tci_internal.log_maint(
    idx.index_id, 'seal_bounded',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    NULL, NULL, n_live_b, n_live_a, n_src, n_chunks, rid,
    pg_wal_lsn_diff(wal1, wal0)::bigint, NULL,
    format('shard=%s n_src=%s n_entries=%s sel_ms=%s enc_ms=%s chunk_ms=%s del_ms=%s',
           shard, n_src, n,
           round(sel_ms::numeric,3), round(enc_ms::numeric,3),
           round(chk_ms::numeric,3), round(del_ms::numeric,3)),
    lock_hold_ms);
  RETURN rid;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.tail_at_least_shard(
  p_index_id int, p_generation bigint, p_shard int, p_n bigint
) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT CASE
    WHEN p_n <= 1 THEN EXISTS (
      SELECT 1 FROM tci_internal.tail
      WHERE index_id = p_index_id AND generation = p_generation AND shard_id = p_shard
      LIMIT 1)
    ELSE EXISTS (
      SELECT 1 FROM tci_internal.tail
      WHERE index_id = p_index_id AND generation = p_generation AND shard_id = p_shard
      OFFSET (p_n - 1) LIMIT 1)
  END
$$;

-- ---------------------------------------------------------------------------
-- compact_budget: merge oldest fan_in live runs on one shard until <= max_runs
-- One merge wave per call (does not loop forever) to avoid starving sealers.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.compact_budget(
  source_table regclass,
  p_shard_id int DEFAULT NULL,
  max_live_runs int DEFAULT 16,
  fan_in int DEFAULT 4,
  max_input_entries int DEFAULT 250000
) RETURNS bigint
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
  n_live int;
  n_live_a int;
  entries_in int;
  bytes_in bigint;
  got_lock boolean;
  shard int;
  wal0 pg_lsn;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  IF max_live_runs < 2 THEN RAISE EXCEPTION 'pg_tci: max_live_runs >= 2'; END IF;
  IF fan_in < 2 OR fan_in > 16 THEN RAISE EXCEPTION 'pg_tci: fan_in in [2,16]'; END IF;

  IF idx.shard_count <= 1 THEN shard := 0;
  ELSE
    IF p_shard_id IS NULL OR p_shard_id < 0 OR p_shard_id >= idx.shard_count THEN
      RAISE EXCEPTION 'pg_tci: p_shard_id required in [0,% )', idx.shard_count;
    END IF;
    shard := p_shard_id;
  END IF;

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard;
  IF n_live <= max_live_runs THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_budget', 0, 0, NULL, NULL, n_live, n_live,
      0, 0, NULL::bigint, 0, 'under_budget',
      format('shard=%s live=%s max=%s', shard, n_live, max_live_runs), 0);
    RETURN NULL;
  END IF;

  wal0 := pg_current_wal_lsn();
  t_lock0 := clock_timestamp();
  got_lock := tci_internal.try_shard_lock(idx.index_id, shard);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_budget', 0, lock_wait_ms, NULL, NULL, n_live, n_live,
      0, 0, NULL::bigint, 0, 'advisory_lock_busy', format('shard=%s', shard), 0);
    RETURN NULL;
  END IF;

  SELECT * INTO idx FROM tci_internal.indexes WHERE index_id = idx.index_id;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  -- Oldest fan_in runs; keep at least 2 even if over entry budget.
  SELECT array_agg(run_id ORDER BY run_id) INTO ids
  FROM (
    WITH ordered AS (
      SELECT run_id, n_entries,
             sum(n_entries) OVER (ORDER BY run_id) AS cum,
             row_number() OVER (ORDER BY run_id) AS rn
      FROM tci_internal.runs
      WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard
    )
    SELECT run_id FROM ordered
    WHERE rn <= fan_in AND (cum <= max_input_entries OR rn <= 2)
  ) x;

  IF ids IS NULL OR array_length(ids, 1) < 2 THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_budget',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live, n_live, 0, 0, NULL::bigint, 0, 'lt_2_runs',
      format('shard=%s', shard), NULL);
    RETURN NULL;
  END IF;

  SELECT coalesce(sum(n_entries),0)::int INTO entries_in
  FROM tci_internal.runs WHERE index_id = idx.index_id AND run_id = ANY (ids);
  SELECT coalesce(sum(octet_length(payload)),0)::bigint INTO bytes_in
  FROM tci_internal.chunks WHERE index_id = idx.index_id AND run_id = ANY (ids);

  IF to_regclass('pg_temp._tci_raw') IS NOT NULL THEN DROP TABLE _tci_raw; END IF;
  CREATE TEMP TABLE _tci_raw (ts timestamptz, delta smallint) ON COMMIT DROP;
  FOR c IN
    SELECT payload FROM tci_internal.chunks
    WHERE index_id = idx.index_id AND run_id = ANY (ids)
    ORDER BY run_id, chunk_id
  LOOP
    INSERT INTO _tci_raw(ts, delta)
    SELECT timestamptz '2000-01-01 00:00:00+00' + (u.ts_us * interval '1 microsecond'), u.delta
    FROM tci_internal.unpack_entries(c.payload) AS u;
  END LOOP;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN DROP TABLE _tci_pref; END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn, ts,
         tci_internal.ts_us(ts) AS ts_us, delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT ts, sum(delta)::bigint AS delta FROM _tci_raw
    GROUP BY ts HAVING sum(delta) <> 0
  ) s;
  SELECT count(*) INTO n FROM _tci_pref;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, shard)
  RETURNING run_id INTO rid;
  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  UPDATE tci_internal.runs SET status = 'retired'
   WHERE index_id = idx.index_id AND run_id = ANY (ids);
  DELETE FROM tci_internal.chunks
   WHERE index_id = idx.index_id AND run_id = ANY (ids);

  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard;

  UPDATE tci_internal.cap_counters
     SET compact_merges = compact_merges + 1,
         compact_txns = compact_txns + 1,
         compact_bytes = compact_bytes + bytes_in,
         compact_ms_sum = compact_ms_sum + EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0
   WHERE index_id = idx.index_id;

  PERFORM tci_internal.log_maint(
    idx.index_id, 'compact_budget',
    (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
    NULL, NULL, n_live, n_live_a, entries_in, NULL, rid,
    pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint, NULL,
    format('shard=%s merged=%s fan_in=%s entries_in=%s', shard, ids, fan_in, entries_in),
    NULL);
  RETURN rid;
END;
$$;

-- compact_pairwise: one 2-way merge when ≥2 live runs on the shard
CREATE OR REPLACE FUNCTION tci.compact_pairwise(
  source_table regclass,
  p_shard_id int DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  shard int;
  n_live int;
BEGIN
  idx := tci_internal.relink_source(source_table);
  IF idx.shard_count <= 1 THEN shard := 0;
  ELSE
    IF p_shard_id IS NULL THEN
      RAISE EXCEPTION 'pg_tci: p_shard_id required';
    END IF;
    shard := p_shard_id;
  END IF;
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard;
  IF n_live < 2 THEN RETURN NULL; END IF;
  -- Force one merge: budget just below current live count.
  RETURN tci.compact_budget(source_table, shard, GREATEST(n_live - 1, 1), 2, 250000);
END;
$$;

-- capacity: expose ingest rates
DROP FUNCTION IF EXISTS tci.capacity(regclass);
CREATE FUNCTION tci.capacity(source_table regclass)
RETURNS TABLE (
  index_id int,
  deltas_sealed bigint,
  seal_txns bigint,
  seal_ms_sum double precision,
  deltas_sealed_per_sec double precision,
  avg_seal_ms double precision,
  deltas_ingested bigint,
  ingest_txns bigint,
  deltas_ingested_per_sec double precision,
  runs_created bigint,
  compact_merges bigint,
  compact_txns bigint,
  compact_bytes bigint,
  compact_bytes_per_sec double precision,
  seconds_since_reset double precision,
  n_tail bigint,
  live_runs int,
  last_seal_at timestamptz
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  idx := tci_internal.relink_source(source_table);
  PERFORM tci_internal.ensure_cap(idx.index_id);
  RETURN QUERY
  SELECT c.index_id, c.deltas_sealed, c.seal_txns, c.seal_ms_sum,
         CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
              THEN (c.deltas_sealed / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
              ELSE 0::float8 END,
         CASE WHEN c.seal_txns > 0 THEN (c.seal_ms_sum / c.seal_txns)::float8 ELSE NULL END,
         c.deltas_ingested,
         c.ingest_txns,
         CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
              THEN (c.deltas_ingested / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
              ELSE 0::float8 END,
         c.runs_created, c.compact_merges, c.compact_txns, c.compact_bytes,
         CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
              THEN (c.compact_bytes / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
              ELSE 0::float8 END,
         EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at))::float8,
         (SELECT count(*) FROM tci_internal.tail t
           WHERE t.index_id = idx.index_id AND t.generation = idx.generation),
         (SELECT count(*)::int FROM tci_internal.runs r
           WHERE r.index_id = idx.index_id AND r.status = 'live'),
         c.last_seal_at
  FROM tci_internal.cap_counters c WHERE c.index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.capacity_reset(source_table regclass)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  PERFORM tci_internal.ensure_cap(idx.index_id);
  UPDATE tci_internal.cap_counters SET
    deltas_sealed=0, seal_txns=0, seal_ms_sum=0,
    deltas_ingested=0, ingest_txns=0, runs_created=0, compact_merges=0,
    compact_txns=0, compact_bytes=0, compact_ms_sum=0,
    select_ms_sum=0, encode_ms_sum=0, chunk_ms_sum=0, delete_ms_sum=0,
    last_seal_at=NULL, last_compact_at=NULL, reset_at=clock_timestamp()
  WHERE index_id = idx.index_id;
END;
$$;

-- Drop old 3-arg seal if present; keep 4-arg with defaults
DROP FUNCTION IF EXISTS tci.seal_bounded(regclass, int, int);

GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int, int, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_budget(regclass, int, int, int, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity_reset(regclass) TO PUBLIC;
