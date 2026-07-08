-- pg_tci 0.1.3 -> 0.1.4
-- 1) Fix v11 race: rebuild/invalidate take the same advisory locks as seal
-- 2) Optional sharded tails (shard_count >= 2) with independent advisory keys
-- 3) Seal phase timing in maint_log.detail

-- ---------------------------------------------------------------------------
-- Schema: sharding + id column for stable hash
-- ---------------------------------------------------------------------------
ALTER TABLE tci_internal.indexes
  ADD COLUMN IF NOT EXISTS id_col name NOT NULL DEFAULT 'id',
  ADD COLUMN IF NOT EXISTS shard_count int NOT NULL DEFAULT 1
    CHECK (shard_count >= 1 AND shard_count <= 64);

ALTER TABLE tci_internal.tail
  ADD COLUMN IF NOT EXISTS shard_id int NOT NULL DEFAULT 0;

ALTER TABLE tci_internal.runs
  ADD COLUMN IF NOT EXISTS shard_id int NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS tail_shard_seek
  ON tci_internal.tail (index_id, generation, shard_id, ts);

ALTER TABLE tci_internal.cap_counters
  ADD COLUMN IF NOT EXISTS delta_rows_seen bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS select_ms_sum double precision NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS encode_ms_sum double precision NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS chunk_ms_sum double precision NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS delete_ms_sum double precision NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION tci_internal.shard_lock_key(
  p_index_id int, p_shard_count int, p_shard_id int
) RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN p_shard_count <= 1 THEN p_index_id
    ELSE p_index_id * 64 + p_shard_id
  END
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
BEGIN
  -- Blocking: wait for in-flight seal/compact on every shard.
  IF n <= 1 THEN
    PERFORM pg_advisory_xact_lock(tci_internal.maint_lock_key1(), p_index_id);
  ELSE
    FOR s IN 0..n - 1 LOOP
      PERFORM pg_advisory_xact_lock(
        tci_internal.maint_lock_key1(),
        tci_internal.shard_lock_key(p_index_id, n, s));
    END LOOP;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.row_shard(
  p_shard_count int, p_id bigint
) RETURNS int
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN p_shard_count <= 1 THEN 0
    ELSE mod(abs(hashtext(p_id::text)), p_shard_count)::int
  END
$$;

-- ---------------------------------------------------------------------------
-- Trigger: KEY SHARE + shard_id from stable id_col
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
    sid := tci_internal.row_shard(idx.shard_count, id_new);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_new, 1);
    IF end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_new, -1);
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
    sid := tci_internal.row_shard(idx.shard_count, id_old);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_old, -1);
    IF end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_old, 1);
    END IF;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
    -- Stable shard from OLD id (PK must not move shards).
    IF id_old IS DISTINCT FROM id_new THEN
      RAISE EXCEPTION 'pg_tci: primary key % change not supported (%/%)',
        idx.id_col, id_old, id_new;
    END IF;
    sid := tci_internal.row_shard(idx.shard_count, id_old);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_old, -1);
    IF end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_old, 1);
    END IF;
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (idx.index_id, idx.generation, sid, start_new, 1);
    IF end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (idx.index_id, idx.generation, sid, end_new, -1);
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- rebuild / invalidate: advisory (all shards) THEN FOR UPDATE
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.rebuild(source_table regclass)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  -- Wait for every in-flight seal/compact (v11 race fix).
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;

  DELETE FROM tci_internal.chunks WHERE index_id = idx.index_id;
  DELETE FROM tci_internal.runs WHERE index_id = idx.index_id;
  DELETE FROM tci_internal.tail WHERE index_id = idx.index_id;

  UPDATE tci_internal.indexes
     SET generation = generation + 1,
         published = false,
         valid = true
   WHERE index_id = idx.index_id
   RETURNING * INTO idx;

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
    SELECT e.ts, sum(e.delta)::bigint AS delta
    FROM tci_internal.event_rows(idx.index_id) e
    GROUP BY e.ts HAVING sum(e.delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;

  IF n > 0 THEN
    INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
    VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, 0)
    RETURNING run_id INTO rid;
    PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);
  END IF;

  UPDATE tci_internal.indexes
     SET published = true,
         valid = true,
         notes = coalesce(notes, '') || format(' [rebuild %s n=%s]', clock_timestamp(), n)
   WHERE index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.invalidate(source_table regclass)
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
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  UPDATE tci_internal.indexes
     SET valid = false,
         published = false,
         notes = coalesce(notes, '') || format(' [invalidated %s]', clock_timestamp())
   WHERE index_id = idx.index_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- seal_bounded(source, max_rows, shard_id)
-- shard_id NULL => shard 0 when shard_count=1; else required
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS tci.seal_bounded(regclass, int);

CREATE OR REPLACE FUNCTION tci.seal_bounded(
  source_table regclass,
  max_rows int DEFAULT 8192,
  p_shard_id int DEFAULT NULL
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
  lock_key2 int;
  gen0 bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;

  IF idx.shard_count <= 1 THEN
    shard := 0;
  ELSE
    IF p_shard_id IS NULL OR p_shard_id < 0 OR p_shard_id >= idx.shard_count THEN
      RAISE EXCEPTION 'pg_tci: p_shard_id required in [0,% )', idx.shard_count;
    END IF;
    shard := p_shard_id;
  END IF;

  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live'
     AND (idx.shard_count <= 1 OR shard_id = shard);

  wal0 := pg_current_wal_lsn();
  lock_key2 := tci_internal.shard_lock_key(idx.index_id, idx.shard_count, shard);
  t_lock0 := clock_timestamp();
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), lock_key2);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      0, 0, NULL::bigint, 0, 'advisory_lock_busy',
      format('shard=%s', shard), 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();

  -- Refresh metadata under lock (detect rebuild/invalidate).
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
  WHERE index_id = idx.index_id
    AND generation = gen0
    AND shard_id = shard
  ORDER BY ts, id
  LIMIT max_rows;
  sel_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_sel0)) * 1000.0;

  SELECT count(*), max(ts) INTO n_src, cutoff FROM _tci_batch;
  IF cutoff IS NULL OR n_src = 0 THEN
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      0, 0, NULL::bigint, 0, 'empty_tail',
      format('shard=%s sel_ms=%s', shard, sel_ms), lock_hold_ms);
    RETURN NULL;
  END IF;

  INSERT INTO _tci_batch(id, ts, delta)
  SELECT t.id, t.ts, t.delta
  FROM tci_internal.tail t
  WHERE t.index_id = idx.index_id
    AND t.generation = gen0
    AND t.shard_id = shard
    AND t.ts = cutoff
    AND NOT EXISTS (SELECT 1 FROM _tci_batch b WHERE b.id = t.id);

  SELECT count(*) INTO n_src FROM _tci_batch;

  t_enc0 := clock_timestamp();
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
  enc_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_enc0)) * 1000.0;

  SELECT count(*) INTO n FROM _tci_pref;

  -- Abort if generation changed (rebuild raced before we held compatible locks).
  IF (SELECT generation FROM tci_internal.indexes WHERE index_id = idx.index_id) <> gen0 THEN
    RAISE EXCEPTION 'pg_tci: generation changed during seal (shard=%)', shard;
  END IF;

  IF n = 0 THEN
    t_del0 := clock_timestamp();
    DELETE FROM tci_internal.tail t
    USING _tci_batch b
    WHERE t.id = b.id;
    del_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_del0)) * 1000.0;
    PERFORM tci_internal.note_seal(idx.index_id, n_src,
      EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'seal_bounded',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b,
      n_src, 0, NULL::bigint,
      pg_wal_lsn_diff(pg_current_wal_lsn(), wal0)::bigint,
      'cancelled_batch',
      format('shard=%s cutoff=%s sel_ms=%s enc_ms=%s del_ms=%s',
             shard, cutoff, sel_ms, enc_ms, del_ms),
      lock_hold_ms);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, shard)
  RETURNING run_id INTO rid;

  t_chk0 := clock_timestamp();
  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);
  chk_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_chk0)) * 1000.0;

  SELECT count(*)::int INTO n_chunks
  FROM tci_internal.chunks WHERE index_id = idx.index_id AND run_id = rid;

  t_del0 := clock_timestamp();
  DELETE FROM tci_internal.tail t
  USING _tci_batch b
  WHERE t.id = b.id;
  del_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_del0)) * 1000.0;

  SELECT count(*)::int INTO n_live_a FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
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
    NULL, NULL, n_live_b, n_live_a,
    n_src, n_chunks, rid, pg_wal_lsn_diff(wal1, wal0)::bigint,
    NULL,
    format('shard=%s cutoff=%s max_rows=%s sel_ms=%s enc_ms=%s chunk_ms=%s del_ms=%s',
           shard, cutoff, max_rows,
           round(sel_ms::numeric, 3), round(enc_ms::numeric, 3),
           round(chk_ms::numeric, 3), round(del_ms::numeric, 3)),
    lock_hold_ms);

  RETURN rid;
END;
$$;

-- compact_pairwise: optional shard filter; advisory per shard
DROP FUNCTION IF EXISTS tci.compact_pairwise(regclass);

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
  shard int;
  lock_key2 int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);

  IF idx.shard_count <= 1 THEN
    shard := 0;
  ELSE
    IF p_shard_id IS NULL OR p_shard_id < 0 OR p_shard_id >= idx.shard_count THEN
      RAISE EXCEPTION 'pg_tci: p_shard_id required in [0,% )', idx.shard_count;
    END IF;
    shard := p_shard_id;
  END IF;

  SELECT count(*)::int INTO n_live_b FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live'
     AND shard_id = shard;
  wal0 := pg_current_wal_lsn();
  lock_key2 := tci_internal.shard_lock_key(idx.index_id, idx.shard_count, shard);
  t_lock0 := clock_timestamp();
  got_lock := pg_try_advisory_xact_lock(tci_internal.maint_lock_key1(), lock_key2);
  lock_wait_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_lock0)) * 1000.0;
  IF NOT got_lock THEN
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_pairwise',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0,
      'advisory_lock_busy', format('shard=%s', shard), 0);
    RETURN NULL;
  END IF;
  t_hold0 := clock_timestamp();
  SELECT * INTO idx FROM tci_internal.indexes WHERE index_id = idx.index_id;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: index for % is not published/valid', source_table;
  END IF;

  SELECT array_agg(run_id ORDER BY run_id) INTO ids
  FROM (
    SELECT run_id FROM tci_internal.runs
    WHERE index_id = idx.index_id AND status = 'live' AND shard_id = shard
    ORDER BY run_id
    LIMIT 2
  ) s;

  IF ids IS NULL OR array_length(ids, 1) < 2 THEN
    lock_hold_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t_hold0)) * 1000.0;
    PERFORM tci_internal.log_maint(
      idx.index_id, 'compact_pairwise',
      (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8, lock_wait_ms,
      NULL, NULL, n_live_b, n_live_b, 0, 0, NULL::bigint, 0, 'lt_2_runs',
      format('shard=%s', shard), lock_hold_ms);
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

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, shard)
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
    NULL, format('shard=%s merged=%s', shard, ids), lock_hold_ms);

  RETURN rid;
END;
$$;

-- Unified create() (drop prior 3-arg overload to avoid ambiguity)
DROP FUNCTION IF EXISTS tci.create(regclass, name, name);
DROP FUNCTION IF EXISTS tci.create(regclass, name, name, int, int, name, int);

CREATE FUNCTION tci.create(
  source_table regclass,
  start_col name,
  end_col name,
  chunk_bytes int DEFAULT 8192,
  cp_interval int DEFAULT 64,
  id_col name DEFAULT 'id',
  shard_count int DEFAULT 1
) RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  nsp name;
  rel name;
  start_ty oid;
  end_ty oid;
  idx_id int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_col AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_col, end_col;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF EXISTS (SELECT 1 FROM tci_internal.indexes WHERE source_oid = source_table) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes WHERE source_nsp = nsp AND source_rel = rel
  ) THEN
    RAISE EXCEPTION 'pg_tci: stale catalog entry for %.% — drop/invalidate first', nsp, rel;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid)
  VALUES (
    source_table, nsp, rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, false, true)
  RETURNING index_id INTO idx_id;

  EXECUTE format(
    'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
     FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
    source_table);

  PERFORM tci.rebuild(source_table);
  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.shard_stats(source_table regclass)
RETURNS TABLE(
  shard_id int,
  n_tail bigint,
  live_runs int,
  n_entries bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  s int;
BEGIN
  idx := tci_internal.relink_source(source_table);
  FOR s IN 0..GREATEST(idx.shard_count, 1) - 1 LOOP
    shard_id := s;
    SELECT count(*) INTO n_tail FROM tci_internal.tail t
     WHERE t.index_id = idx.index_id AND t.generation = idx.generation AND t.shard_id = s;
    SELECT count(*)::int, coalesce(sum(r.n_entries),0)
      INTO live_runs, n_entries
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live' AND r.shard_id = s;
    RETURN NEXT;
  END LOOP;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.shard_stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO PUBLIC;
REVOKE ALL ON FUNCTION tci.rebuild(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.rebuild(regclass) TO PUBLIC;
REVOKE ALL ON FUNCTION tci.invalidate(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.invalidate(regclass) TO PUBLIC;
