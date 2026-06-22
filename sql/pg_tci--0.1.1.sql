-- pg_tci 0.1.1-preview (full install)
-- Temporal Coverage Index — packed IAR + maintain/security hardening

-- pg_tci 0.1.0-preview
-- Temporal Coverage Index — packed IAR for interval COUNT [start, end)
-- Not an Index Access Method. Source table remains source of truth.

-- ---------------------------------------------------------------------------
-- Internal schema (storage, not public API)
-- ---------------------------------------------------------------------------
CREATE SCHEMA tci_internal;

COMMENT ON SCHEMA tci_internal IS
  'pg_tci internal catalog, packed runs/chunks, and MVCC tails';

-- ---------------------------------------------------------------------------
-- Native C codec (TCIP v1)
-- Volatility: pure memory transforms of arguments → IMMUTABLE STRICT.
-- PARALLEL SAFE: no shared mutable state, no catalog access, no SPI.
-- ---------------------------------------------------------------------------
CREATE FUNCTION tci_internal.chunk_prefix_at(encoded bytea, timestamp_us bigint)
RETURNS bigint
LANGUAGE C
IMMUTABLE
STRICT
PARALLEL SAFE
AS 'MODULE_PATHNAME', 'pg_tci_chunk_prefix_at';

CREATE FUNCTION tci_internal.pack_entries(ts_us bigint[], deltas smallint[], cp_interval int)
RETURNS bytea
LANGUAGE C
IMMUTABLE
STRICT
PARALLEL SAFE
AS 'MODULE_PATHNAME', 'pg_tci_pack_entries';

CREATE FUNCTION tci_internal.pack_validate(encoded bytea)
RETURNS boolean
LANGUAGE C
IMMUTABLE
STRICT
PARALLEL SAFE
AS 'MODULE_PATHNAME', 'pg_tci_pack_validate';

-- SRF: mark PARALLEL RESTRICTED (set-returning; safer default for preview)
CREATE FUNCTION tci_internal.unpack_entries(encoded bytea)
RETURNS TABLE(ts_us bigint, delta smallint)
LANGUAGE C
STRICT
PARALLEL RESTRICTED
AS 'MODULE_PATHNAME', 'pg_tci_unpack_entries';

-- timestamptz → PostgreSQL epoch µs (matches timestamptz_send)
CREATE FUNCTION tci_internal.ts_us(p timestamptz)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  b bytea := timestamptz_send(p);
  r bigint;
  i int;
  hi int;
BEGIN
  hi := get_byte(b, 0);
  IF hi >= 128 THEN r := (hi - 256)::bigint; ELSE r := hi::bigint; END IF;
  FOR i IN 1..7 LOOP
    r := (r << 8) + get_byte(b, i);
  END LOOP;
  RETURN r;
END;
$$;

-- ---------------------------------------------------------------------------
-- Catalog + packed storage
-- ---------------------------------------------------------------------------
CREATE TABLE tci_internal.indexes (
  index_id      serial PRIMARY KEY,
  source_oid    oid NOT NULL UNIQUE,
  source_nsp    name NOT NULL,
  source_rel    name NOT NULL,
  start_col     name NOT NULL,
  end_col       name NOT NULL,
  generation    bigint NOT NULL DEFAULT 1,
  published     boolean NOT NULL DEFAULT false,
  valid         boolean NOT NULL DEFAULT true,
  chunk_bytes   int NOT NULL DEFAULT 8192
                  CHECK (chunk_bytes IN (4096, 8192, 16384, 32768)),
  cp_interval   int NOT NULL DEFAULT 64
                  CHECK (cp_interval IN (32, 64, 128)),
  created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  notes         text
);

CREATE TABLE tci_internal.runs (
  index_id      int NOT NULL REFERENCES tci_internal.indexes ON DELETE CASCADE,
  run_id        bigserial,
  status        text NOT NULL CHECK (status IN ('live', 'retired')),
  n_entries     int NOT NULL,
  chunk_bytes   int NOT NULL,
  cp_interval   int NOT NULL,
  sealed_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (index_id, run_id)
);

CREATE TABLE tci_internal.chunks (
  index_id      int NOT NULL,
  run_id        bigint NOT NULL,
  chunk_id      int NOT NULL,
  ts_min        timestamptz NOT NULL,
  ts_max        timestamptz NOT NULL,
  ts_min_us     bigint NOT NULL,
  ts_max_us     bigint NOT NULL,
  prefix_before bigint NOT NULL,
  n_entries     int NOT NULL,
  payload       bytea NOT NULL,
  PRIMARY KEY (index_id, run_id, chunk_id),
  FOREIGN KEY (index_id, run_id)
    REFERENCES tci_internal.runs (index_id, run_id) ON DELETE CASCADE
);

CREATE INDEX chunks_seek
  ON tci_internal.chunks (index_id, run_id, ts_min_us);

CREATE TABLE tci_internal.tail (
  id            bigserial PRIMARY KEY,
  index_id      int NOT NULL REFERENCES tci_internal.indexes ON DELETE CASCADE,
  generation    bigint NOT NULL,
  ts            timestamptz NOT NULL,
  delta         smallint NOT NULL CHECK (delta IN (-1, 1))
);

CREATE INDEX tail_seek
  ON tci_internal.tail (index_id, generation, ts);

-- Persist user index data across pg_dump
SELECT pg_catalog.pg_extension_config_dump('tci_internal.indexes', '');
SELECT pg_catalog.pg_extension_config_dump('tci_internal.runs', '');
SELECT pg_catalog.pg_extension_config_dump('tci_internal.chunks', '');
SELECT pg_catalog.pg_extension_config_dump('tci_internal.tail', '');

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------
CREATE FUNCTION tci_internal.native_count(
  p_source regclass,
  p_start name,
  p_end name,
  p_ts timestamptz
) RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v bigint;
  q text;
BEGIN
  -- [start, end): start <= ts AND (end IS NULL OR end > ts)
  q := format(
    'SELECT count(*)::bigint FROM %s s WHERE s.%I <= $1 AND (s.%I IS NULL OR s.%I > $1)',
    p_source, p_start, p_end, p_end);
  EXECUTE q INTO v USING p_ts;
  RETURN v;
END;
$$;

CREATE FUNCTION tci_internal.tail_sum(p_index_id int, p_ts timestamptz)
RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT COALESCE(sum(t.delta), 0)::bigint
  FROM tci_internal.tail t
  JOIN tci_internal.indexes i ON i.index_id = t.index_id
  WHERE t.index_id = p_index_id
    AND t.generation = i.generation
    AND i.published
    AND t.ts <= p_ts;
$$;

CREATE FUNCTION tci_internal.run_prefix_at(p_index_id int, p_run_id bigint, p_ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  c RECORD;
  target_us bigint := tci_internal.ts_us(p_ts);
  local_prefix bigint;
BEGIN
  SELECT * INTO c
  FROM tci_internal.chunks
  WHERE index_id = p_index_id
    AND run_id = p_run_id
    AND ts_min_us <= target_us
  ORDER BY ts_min_us DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  local_prefix := tci_internal.chunk_prefix_at(c.payload, target_us);
  RETURN c.prefix_before + local_prefix;
END;
$$;

CREATE FUNCTION tci_internal.insert_chunks(
  p_index_id int,
  p_run_id bigint,
  p_chunk_bytes int,
  p_cp_interval int
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  n int;
  epc int;
  lo int;
  hi int;
  chunk_i int := 0;
  ts_arr timestamptz[];
  d_arr smallint[];
  us_arr bigint[];
  base_pref bigint;
  payload bytea;
BEGIN
  SELECT count(*) INTO n FROM _tci_pref;
  epc := GREATEST(p_cp_interval, p_chunk_bytes / 4);
  FOR lo IN 1..n BY epc LOOP
    hi := LEAST(lo + epc - 1, n);
    SELECT array_agg(ts ORDER BY rn),
           array_agg(delta ORDER BY rn),
           array_agg(ts_us ORDER BY rn)
      INTO ts_arr, d_arr, us_arr
    FROM _tci_pref
    WHERE rn BETWEEN lo AND hi;

    IF lo = 1 THEN
      base_pref := 0;
    ELSE
      SELECT prefix_sum INTO base_pref FROM _tci_pref WHERE rn = lo - 1;
    END IF;

    payload := tci_internal.pack_entries(us_arr, d_arr, p_cp_interval);

    INSERT INTO tci_internal.chunks(
      index_id, run_id, chunk_id, ts_min, ts_max, ts_min_us, ts_max_us,
      prefix_before, n_entries, payload)
    VALUES (
      p_index_id, p_run_id, chunk_i,
      ts_arr[1], ts_arr[array_length(ts_arr, 1)],
      us_arr[1], us_arr[array_length(us_arr, 1)],
      base_pref, array_length(ts_arr, 1),
      payload);
    chunk_i := chunk_i + 1;
  END LOOP;
END;
$$;

-- Trigger: append MVCC deltas for published indexes
CREATE FUNCTION tci_internal.source_trig()
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
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID
  FOR SHARE;

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

REVOKE ALL ON FUNCTION tci_internal.source_trig() FROM PUBLIC;

CREATE FUNCTION tci_internal.event_rows(p_index_id int)
RETURNS TABLE(ts timestamptz, delta smallint)
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  q text;
BEGIN
  SELECT * INTO STRICT idx FROM tci_internal.indexes WHERE index_id = p_index_id;
  q := format(
    $f$
      SELECT s.%I, 1::smallint FROM %I.%I s
      UNION ALL
      SELECT s.%I, (-1)::smallint FROM %I.%I s WHERE s.%I IS NOT NULL
    $f$,
    idx.start_col, idx.source_nsp, idx.source_rel,
    idx.end_col, idx.source_nsp, idx.source_rel, idx.end_col);
  RETURN QUERY EXECUTE q;
END;
$$;

-- ---------------------------------------------------------------------------
-- Public API (schema tci)
-- ---------------------------------------------------------------------------
CREATE SCHEMA tci;

COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.0-preview)';

CREATE FUNCTION tci.create(
  source_table regclass,
  start_column name,
  end_column name
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
  trig_name name;
BEGIN
  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;

  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty
  FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty
  FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;

  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.% / %.% not found',
      source_table, start_column, source_table, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  IF EXISTS (SELECT 1 FROM tci_internal.indexes WHERE source_oid = source_table) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col, published, valid)
  VALUES (source_table, nsp, rel, start_column, end_column, false, true)
  RETURNING index_id INTO idx_id;

  trig_name := format('tci_mvcc_%s', idx_id);
  EXECUTE format(
    'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s
     FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
    trig_name, source_table);

  -- Initial build from existing rows, then publish
  PERFORM tci.rebuild(source_table);

  RETURN idx_id;
END;
$$;

-- After pg_restore, table OIDs may change; rematch by schema+relation name.
CREATE FUNCTION tci_internal.relink_source(source_table regclass)
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
BEGIN
  SELECT * INTO idx FROM tci_internal.indexes WHERE source_oid = source_table;
  IF FOUND THEN
    RETURN idx;
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;

  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_nsp = nsp AND source_rel = rel
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: no index for % — call tci.create first', source_table;
  END IF;

  new_oid := source_table;
  -- OID changed under same name (drop/recreate or restore): fail closed until rebuild
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
    WHERE tgrelid = new_oid AND tgname = format('tci_mvcc_%s', idx.index_id)
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      format('tci_mvcc_%s', idx.index_id), new_oid::regclass);
  END IF;

  RETURN idx;
END;
$$;

CREATE FUNCTION tci.invalidate(source_table regclass)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  idx := tci_internal.relink_source(source_table);
  UPDATE tci_internal.indexes
     SET valid = false,
         published = false,
         notes = coalesce(notes, '') || format(' [invalidated %s]', clock_timestamp())
   WHERE index_id = idx.index_id;
END;
$$;

CREATE FUNCTION tci.count_at(source_table regclass, ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  total bigint := 0;
  r RECORD;
BEGIN
  idx := tci_internal.relink_source(source_table);

  -- Fail closed on invalid: native COUNT (never return stale packed aggregates)
  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count(
      source_table, idx.start_col, idx.end_col, ts);
  END IF;

  FOR r IN
    SELECT run_id FROM tci_internal.runs
    WHERE index_id = idx.index_id AND status = 'live'
  LOOP
    total := total + tci_internal.run_prefix_at(idx.index_id, r.run_id, ts);
  END LOOP;

  RETURN total + tci_internal.tail_sum(idx.index_id, ts);
END;
$$;

CREATE FUNCTION tci.stats(source_table regclass)
RETURNS TABLE(
  index_id int,
  published boolean,
  valid boolean,
  generation bigint,
  live_runs bigint,
  retired_runs bigint,
  n_chunks bigint,
  n_tail bigint,
  chunk_bytes int,
  cp_interval int,
  chunks_bytes bigint,
  notes text
)
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  idx := tci_internal.relink_source(source_table);

  index_id := idx.index_id;
  published := idx.published;
  valid := idx.valid;
  generation := idx.generation;
  chunk_bytes := idx.chunk_bytes;
  cp_interval := idx.cp_interval;
  notes := idx.notes;

  SELECT count(*) INTO live_runs FROM tci_internal.runs
   WHERE tci_internal.runs.index_id = idx.index_id AND status = 'live';
  SELECT count(*) INTO retired_runs FROM tci_internal.runs
   WHERE tci_internal.runs.index_id = idx.index_id AND status = 'retired';
  SELECT count(*) INTO n_chunks FROM tci_internal.chunks
   WHERE tci_internal.chunks.index_id = idx.index_id;
  SELECT count(*) INTO n_tail FROM tci_internal.tail t
   WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
  SELECT COALESCE(sum(pg_column_size(c.payload)), 0) INTO chunks_bytes
   FROM tci_internal.chunks c WHERE c.index_id = idx.index_id;

  RETURN NEXT;
END;
$$;

CREATE FUNCTION tci.seal(source_table regclass)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
BEGIN
  idx := tci_internal.relink_source(source_table);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
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
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  DELETE FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = idx.generation;

  RETURN rid;
END;
$$;

CREATE FUNCTION tci.compact(source_table regclass)
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
BEGIN
  idx := tci_internal.relink_source(source_table);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
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

  -- Atomic publication: retire old, delete old chunks (MVCC DELETE)
  UPDATE tci_internal.runs SET status = 'retired'
   WHERE index_id = idx.index_id AND run_id = ANY (ids);
  DELETE FROM tci_internal.chunks
   WHERE index_id = idx.index_id AND run_id = ANY (ids);

  RETURN rid;
END;
$$;

CREATE FUNCTION tci.rebuild(source_table regclass)
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
  idx := tci_internal.relink_source(source_table);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;

  -- Drop sealed state; rebuild from source; bump generation; publish atomically
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
    INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
    VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
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

-- Event triggers for DDL invalidation
CREATE FUNCTION tci_internal.ddl_invalidate()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF r.objid IS NOT NULL THEN
      UPDATE tci_internal.indexes
         SET valid = false,
             published = false,
             notes = coalesce(notes, '') || format(' [DDL %s]', clock_timestamp())
       WHERE source_oid = r.objid;
    END IF;
  END LOOP;
END;
$$;

CREATE FUNCTION tci_internal.drop_invalidate()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
    IF r.object_type IN ('table', 'table column') THEN
      DELETE FROM tci_internal.indexes WHERE source_oid = r.objid;
    END IF;
  END LOOP;
END;
$$;

CREATE EVENT TRIGGER tci_ddl_invalidate
  ON ddl_command_end
  WHEN TAG IN ('ALTER TABLE')
  EXECUTE FUNCTION tci_internal.ddl_invalidate();

CREATE EVENT TRIGGER tci_drop_invalidate
  ON sql_drop
  EXECUTE FUNCTION tci_internal.drop_invalidate();

-- ---- 0.1.1 hardening (also in pg_tci--0.1.0--0.1.1.sql) ----
COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.1-preview)';

-- ---------------------------------------------------------------------------
-- Privilege helpers
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.require_select(source_table regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  -- Must use session_user: under SECURITY DEFINER, current_user is the owner.
  IF NOT has_table_privilege(session_user, source_table, 'SELECT') THEN
    RAISE EXCEPTION 'pg_tci: permission denied for SELECT on %', source_table
      USING ERRCODE = '42501';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.require_admin(source_table regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  owner oid;
BEGIN
  SELECT c.relowner INTO owner FROM pg_class c WHERE c.oid = source_table;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;
  -- session_user: SECURITY DEFINER must not authorize as the function owner
  IF NOT pg_has_role(session_user, owner, 'MEMBER')
     AND NOT has_table_privilege(session_user, source_table, 'TRIGGER') THEN
    RAISE EXCEPTION
      'pg_tci: permission denied — need table ownership or TRIGGER on %',
      source_table
      USING ERRCODE = '42501';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION tci_internal.require_select(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.require_admin(regclass) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Hardened relink: never silently bind to an unrelated table
-- ---------------------------------------------------------------------------
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
  -- Prefer exact OID match
  SELECT * INTO idx FROM tci_internal.indexes WHERE source_oid = source_table;
  IF FOUND THEN
    -- Identity sanity: names still match; columns still timestamptz
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

  -- Refuse if another live OID already claims this catalog row conflict
  SELECT count(*) INTO conflict
  FROM tci_internal.indexes i
  WHERE i.index_id <> idx.index_id
    AND i.source_oid = source_table;
  IF conflict > 0 THEN
    RAISE EXCEPTION
      'pg_tci: refusing relink — OID % already bound to another index',
      source_table;
  END IF;

  -- Column type check before rebind
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

  -- Stale OID must not still resolve to a different live relation of same name
  -- (drop+recreate same name is allowed only after type checks above)
  new_oid := source_table;
  -- OID changed under same name (drop/recreate or restore): fail closed until rebuild
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
    WHERE tgrelid = new_oid AND tgname = format('tci_mvcc_%s', idx.index_id)
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      format('tci_mvcc_%s', idx.index_id), new_oid::regclass);
  END IF;

  RETURN idx;
END;
$$;

-- ---------------------------------------------------------------------------
-- Wrap public APIs with privilege checks (recreate with SECURITY DEFINER where needed)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create(
  source_table regclass,
  start_column name,
  end_column name
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
  trig_name name;
BEGIN
  PERFORM tci_internal.require_admin(source_table);

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;

  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty
  FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty
  FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;

  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.% / %.% not found',
      source_table, start_column, source_table, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
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
    source_oid, source_nsp, source_rel, start_col, end_col, published, valid)
  VALUES (source_table, nsp, rel, start_column, end_column, false, true)
  RETURNING index_id INTO idx_id;

  trig_name := format('tci_mvcc_%s', idx_id);
  EXECUTE format(
    'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s
     FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
    trig_name, source_table);

  PERFORM tci.rebuild(source_table);
  RETURN idx_id;
END;
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
  total bigint := 0;
  r RECORD;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count(
      source_table, idx.start_col, idx.end_col, ts);
  END IF;

  FOR r IN
    SELECT run_id FROM tci_internal.runs
    WHERE index_id = idx.index_id AND status = 'live'
  LOOP
    total := total + tci_internal.run_prefix_at(idx.index_id, r.run_id, ts);
  END LOOP;

  RETURN total + tci_internal.tail_sum(idx.index_id, ts);
END;
$$;

CREATE OR REPLACE FUNCTION tci.stats(source_table regclass)
RETURNS TABLE(
  index_id int,
  published boolean,
  valid boolean,
  generation bigint,
  live_runs bigint,
  retired_runs bigint,
  n_chunks bigint,
  n_tail bigint,
  chunk_bytes int,
  cp_interval int,
  chunks_bytes bigint,
  notes text
)
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);

  index_id := idx.index_id;
  published := idx.published;
  valid := idx.valid;
  generation := idx.generation;
  chunk_bytes := idx.chunk_bytes;
  cp_interval := idx.cp_interval;
  notes := idx.notes;

  SELECT count(*) INTO live_runs FROM tci_internal.runs
   WHERE tci_internal.runs.index_id = idx.index_id AND status = 'live';
  SELECT count(*) INTO retired_runs FROM tci_internal.runs
   WHERE tci_internal.runs.index_id = idx.index_id AND status = 'retired';
  SELECT count(*) INTO n_chunks FROM tci_internal.chunks
   WHERE tci_internal.chunks.index_id = idx.index_id;
  SELECT count(*) INTO n_tail FROM tci_internal.tail t
   WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
  SELECT COALESCE(sum(pg_column_size(c.payload)), 0) INTO chunks_bytes
   FROM tci_internal.chunks c WHERE c.index_id = idx.index_id;

  RETURN NEXT;
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
  UPDATE tci_internal.indexes
     SET valid = false,
         published = false,
         notes = coalesce(notes, '') || format(' [invalidated %s]', clock_timestamp())
   WHERE index_id = idx.index_id;
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
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
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
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  DELETE FROM tci_internal.tail
  WHERE index_id = idx.index_id AND generation = idx.generation;

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
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
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
    INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval)
    VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval)
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

-- ---------------------------------------------------------------------------
-- tci.maintain — seal/compact under thresholds with advisory lock + budget
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.maintain(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8,
  budget_ms int DEFAULT 5000,
  max_active_writers int DEFAULT 8
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
  t0 timestamptz;
  t1 timestamptz;
  elapsed_ms double precision := 0;
  n_writers int := 0;
  lock_key1 int := 88442201; -- pg_tci maintain namespace
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

  IF tail_target < 1 OR max_live_runs < 2 OR budget_ms < 1 THEN
    RAISE EXCEPTION 'pg_tci: invalid maintain thresholds';
  END IF;

  lock_key2 := idx.index_id;
  got_lock := pg_try_advisory_xact_lock(lock_key1, lock_key2);
  IF NOT got_lock THEN
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    SELECT count(*) INTO n_tail FROM tci_internal.tail
     WHERE index_id = idx.index_id AND generation = idx.generation;
    SELECT count(*)::int INTO n_live FROM tci_internal.runs
     WHERE index_id = idx.index_id AND status = 'live';
    n_tail_before := n_tail; n_live_before := n_live;
    n_tail_after := n_tail; n_live_after := n_live;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := 'advisory_lock_busy';
    writer_activity := 0; lock_acquired := false;
    RETURN NEXT; RETURN;
  END IF;

  -- Approximate writer activity on the source relation
  SELECT count(*)::int INTO n_writers
  FROM pg_stat_activity a
  WHERE a.pid <> pg_backend_pid()
    AND a.datid = (SELECT oid FROM pg_database WHERE datname = current_database())
    AND a.state IN ('active', 'idle in transaction')
    AND a.wait_event_type IS DISTINCT FROM 'Client'
    AND a.query ILIKE '%' || idx.source_rel || '%'
    AND (a.query ILIKE '%INSERT%' OR a.query ILIKE '%UPDATE%' OR a.query ILIKE '%DELETE%');

  SELECT count(*) INTO n_tail FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  n_tail_before := n_tail;
  n_live_before := n_live;

  IF n_writers > max_active_writers THEN
    sealed := false; compacted := false;
    seal_run_id := NULL; compact_run_id := NULL;
    n_tail_after := n_tail; n_live_after := n_live;
    seal_ms := NULL; compact_ms := NULL;
    skipped_reason := format('writer_activity=%s', n_writers);
    writer_activity := n_writers; lock_acquired := true;
    RETURN NEXT; RETURN;
  END IF;

  t0 := clock_timestamp();

  -- Seal when tail exceeds target
  IF n_tail >= tail_target THEN
    t1 := clock_timestamp();
    s_rid := tci.seal(source_table);
    s_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_seal := s_rid IS NOT NULL;
    elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0;
  END IF;

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  -- Hybrid compact: when live runs exceed max (and budget remains)
  IF n_live > max_live_runs AND elapsed_ms < budget_ms THEN
    t1 := clock_timestamp();
    c_rid := tci.compact(source_table);
    c_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_compact := c_rid IS NOT NULL;
    elapsed_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0;
  ELSIF n_live > max_live_runs AND elapsed_ms >= budget_ms THEN
    skip := 'budget_exhausted_before_compact';
  END IF;

  -- Optional second compact pass if still over max and budget remains
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';
  IF n_live > max_live_runs AND elapsed_ms < budget_ms THEN
    t1 := clock_timestamp();
    PERFORM tci.compact(source_table);
    c_ms := COALESCE(c_ms, 0) + EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_compact := true;
  END IF;

  SELECT count(*) INTO n_tail FROM tci_internal.tail
   WHERE index_id = idx.index_id AND generation = idx.generation;
  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  IF skip IS NULL AND NOT did_seal AND NOT did_compact THEN
    skip := 'below_thresholds';
  END IF;

  sealed := did_seal;
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
  RETURN NEXT;
END;
$$;

-- Privileges: PUBLIC may count/stats; admin APIs not granted to PUBLIC

-- Schema usage required for public API resolution
GRANT USAGE ON SCHEMA tci TO PUBLIC;
REVOKE ALL ON FUNCTION tci.create(regclass, name, name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.seal(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.compact(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.invalidate(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.rebuild(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maintain(regclass, int, int, int, int) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.stats(regclass) TO PUBLIC;

-- Extension owner / superuser retains admin via ownership of functions
GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name) TO PUBLIC; -- gated by require_admin
GRANT EXECUTE ON FUNCTION tci.seal(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.invalidate(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.rebuild(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.maintain(regclass, int, int, int, int) TO PUBLIC;

-- Note: EXECUTE is PUBLIC but SECURITY DEFINER bodies enforce ownership/TRIGGER
-- and SELECT. Unprivileged callers without those rights fail closed.

REVOKE ALL ON SCHEMA tci_internal FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA tci_internal FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA tci_internal FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA tci_internal FROM PUBLIC;
