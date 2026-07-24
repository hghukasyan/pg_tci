-- pg_tci 0.1.5 → 0.1.6
-- Single measured optimization: PK ANY-array DELETE for seal_bounded batches.
-- Avoids Hash Join + Seq Scan on large tails (dominant under concurrent COUNT).
-- Also: one-time invalidate of sharded indexes until rebuild after routing_v1 era.

CREATE TABLE IF NOT EXISTS tci_internal.ext_meta (
  key text PRIMARY KEY,
  value text NOT NULL
);

-- If sharded indexes may still carry pre-v1 hashtext routing from a 0.1.4→0.1.5
-- upgrade that did not invalidate, force rebuild before serving counts.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM tci_internal.ext_meta WHERE key = 'routing_v1_migrated'
  ) THEN
    UPDATE tci_internal.indexes
       SET valid = false
     WHERE shard_count > 1 AND valid;
    INSERT INTO tci_internal.ext_meta(key, value)
    VALUES ('routing_v1_migrated', '1');
  END IF;
END;
$$;

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
  batch_ids bigint[];
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

  -- Materialize PK list once for Index Scan deletes (avoid Hash+SeqScan on huge tails).
  SELECT array_agg(id) INTO batch_ids FROM _tci_batch;

  IF n = 0 THEN
    t_del0 := clock_timestamp();
    DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);
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

  -- Publish run first; delete selected tail rows in the same transaction (exact-once).
  t_del0 := clock_timestamp();
  DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);
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
    format('shard=%s n_src=%s n_entries=%s sel_ms=%s enc_ms=%s chunk_ms=%s del_ms=%s del=any',
           shard, n_src, n,
           round(sel_ms::numeric,3), round(enc_ms::numeric,3),
           round(chk_ms::numeric,3), round(del_ms::numeric,3)),
    lock_hold_ms);
  RETURN rid;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int, int, int) TO PUBLIC;

-- Fresh installs stamp routing migration so new indexes stay valid.
INSERT INTO tci_internal.ext_meta(key, value)
VALUES ('routing_v1_migrated', '1')
ON CONFLICT (key) DO NOTHING;
