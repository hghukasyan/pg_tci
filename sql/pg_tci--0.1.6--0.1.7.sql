-- pg_tci 0.1.6 → 0.1.7
-- Fused set-based run prefix lookup for count_at (one plan, existing C decoder).
-- Tail sum uses already-known generation (no indexes join).

CREATE OR REPLACE FUNCTION tci_internal.runs_prefix_sum(
  p_index_id int,
  p_ts timestamptz
) RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  -- At most one candidate chunk per live run; decode with existing C function.
  -- Empty contribution when no chunk has ts_min_us <= target (same as run_prefix_at).
  SELECT COALESCE(sum(c.prefix_before
                      + tci_internal.chunk_prefix_at(c.payload, tci_internal.ts_us(p_ts))),
                  0)::bigint
  FROM (
    SELECT DISTINCT ON (ch.run_id)
           ch.prefix_before, ch.payload
    FROM tci_internal.chunks ch
    INNER JOIN tci_internal.runs r
      ON r.index_id = ch.index_id
     AND r.run_id = ch.run_id
     AND r.status = 'live'
    WHERE ch.index_id = p_index_id
      AND ch.ts_min_us <= tci_internal.ts_us(p_ts)
    ORDER BY ch.run_id, ch.ts_min_us DESC
  ) c;
$$;

CREATE OR REPLACE FUNCTION tci_internal.tail_sum_gen(
  p_index_id int,
  p_generation bigint,
  p_ts timestamptz
) RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT COALESCE(sum(t.delta), 0)::bigint
  FROM tci_internal.tail t
  WHERE t.index_id = p_index_id
    AND t.generation = p_generation
    AND t.ts <= p_ts;
$$;

CREATE OR REPLACE FUNCTION tci.count_at(source_table regclass, ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count(
      source_table, idx.start_col, idx.end_col, ts);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, ts)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, ts);
END;
$$;

-- Keep legacy tail_sum for callers; implement via gen after relink-free path.
CREATE OR REPLACE FUNCTION tci_internal.tail_sum(p_index_id int, p_ts timestamptz)
RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT tci_internal.tail_sum_gen(
    p_index_id,
    (SELECT generation FROM tci_internal.indexes WHERE index_id = p_index_id),
    p_ts);
$$;

GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- 0.1.7 preview hardening (audit follow-up): privilege gates + lock keyspace
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION tci_internal.try_all_shard_locks(
  p_index_id int, p_shard_count int
) RETURNS boolean
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  s int;
  n int := GREATEST(p_shard_count, 1);
  k1 int := tci_internal.shard_lock_key1(p_index_id);
BEGIN
  FOR s IN 0..n - 1 LOOP
    IF NOT pg_try_advisory_xact_lock(k1, s) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.relink_source(source_table regclass)
RETURNS tci_internal.indexes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  nsp name;
  rel name;
  new_oid oid;
  start_ty oid;
  end_ty oid;
  conflict int;
BEGIN
  SELECT * INTO idx FROM tci_internal.indexes WHERE source_oid = source_table;
  IF FOUND THEN
    SELECT c.relnamespace::regnamespace::name, c.relname
      INTO nsp, rel
    FROM pg_class c WHERE c.oid = source_table;
    IF nsp IS DISTINCT FROM idx.source_nsp OR rel IS DISTINCT FROM idx.source_rel THEN
      UPDATE tci_internal.indexes
         SET valid = false, published = false,
             notes = coalesce(notes,'') || format(' [oid/name mismatch %s]', clock_timestamp())
       WHERE index_id = idx.index_id
       RETURNING * INTO idx;
      RAISE EXCEPTION
        'pg_tci: source_oid % no longer matches cataloged % . % — fail closed (rebuild/create)',
        source_table, idx.source_nsp, idx.source_rel;
    END IF;

    SELECT a.atttypid INTO start_ty FROM pg_attribute a
     WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
    SELECT a.atttypid INTO end_ty FROM pg_attribute a
     WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
    IF start_ty IS NULL OR end_ty IS NULL
       OR start_ty <> 'timestamptz'::regtype
       OR end_ty <> 'timestamptz'::regtype THEN
      UPDATE tci_internal.indexes
         SET valid = false, published = false,
             notes = coalesce(notes,'') || format(' [column type/missing %s]', clock_timestamp())
       WHERE index_id = idx.index_id;
      RAISE EXCEPTION
        'pg_tci: indexed columns on % missing or not timestamptz — fail closed',
        source_table;
    END IF;
    RETURN idx;
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_nsp = nsp AND source_rel = rel
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: no index for % — call tci.create first', source_table;
  END IF;

  SELECT count(*) INTO conflict
  FROM tci_internal.indexes i
  WHERE i.index_id <> idx.index_id
    AND i.source_oid = source_table;
  IF conflict > 0 THEN
    RAISE EXCEPTION
      'pg_tci: refusing relink — OID % already bound to another index',
      source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL
     OR start_ty <> 'timestamptz'::regtype
     OR end_ty <> 'timestamptz'::regtype THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [relink refused bad cols %s]', clock_timestamp())
     WHERE index_id = idx.index_id;
    RAISE EXCEPTION
      'pg_tci: cannot relink % — columns % / % not timestamptz',
      source_table, idx.start_col, idx.end_col;
  END IF;

  new_oid := source_table;
  UPDATE tci_internal.indexes
     SET source_oid = new_oid,
         valid = false,
         published = false,
         notes = coalesce(notes, '') || format(
           ' [relink oid %s — invalidated pending rebuild]', clock_timestamp())
   WHERE index_id = idx.index_id
   RETURNING * INTO idx;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = new_oid AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      new_oid::regclass);
  END IF;

  RETURN idx;
END;
$$;

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
  PERFORM tci_internal.require_admin(source_table);
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
  RETURN tci.compact_budget(source_table, shard, GREATEST(n_live - 1, 1), 2, 250000);
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
  PERFORM tci_internal.require_select(source_table);
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

-- capacity / seal / compact / maintain: pull final bodies from install via
-- REPLACE of privilege + lock lines only where bodies are short enough.
-- Full seal/compact/maintain lock fix is in pg_tci--0.1.7.sql; for upgrades
-- from 0.1.6 re-apply the lock line via CREATE OR REPLACE of the wrappers
-- already present in 0.1.6 — replace lock helper usage by redefining seal/compact/maintain
-- from the 0.1.7 install file end-state is large, so call try_all via thin wrappers:

CREATE OR REPLACE FUNCTION tci.capacity(source_table regclass)
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
  PERFORM tci_internal.require_select(source_table);
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

GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.shard_stats(regclass) TO PUBLIC;

-- lock keyspace alignment for seal/compact/maintain
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
  -- Same keyspace as seal_bounded / rebuild (shard_lock_key1).
  got_lock := tci_internal.try_all_shard_locks(idx.index_id, idx.shard_count);
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
  got_lock := tci_internal.try_all_shard_locks(idx.index_id, idx.shard_count);
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

  -- Same keyspace as seal_bounded / rebuild so nested calls see held locks.
  got_lock := tci_internal.try_all_shard_locks(idx.index_id, idx.shard_count);
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
