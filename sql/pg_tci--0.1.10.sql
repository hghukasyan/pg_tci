-- pg_tci 0.1.5-preview (full install)
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
  -- KEY SHARE: blocks rebuild FOR UPDATE; compatible with advisory seal path
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

  -- Match tci.create: single fixed trigger name per source table.
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

  t0 := clock_timestamp();

  -- Seal when tail exceeds target
  IF n_tail >= tail_target THEN
    t1 := clock_timestamp();
    s_rid := tci.seal(source_table);
    s_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_seal := s_rid IS NOT NULL;
    elapsed_ms := (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8;
  END IF;

  SELECT count(*)::int INTO n_live FROM tci_internal.runs
   WHERE index_id = idx.index_id AND status = 'live';

  -- Hybrid compact: when live runs exceed max (and budget remains)
  IF n_live > max_live_runs AND elapsed_ms < budget_ms THEN
    t1 := clock_timestamp();
    c_rid := tci.compact(source_table);
    c_ms := EXTRACT(EPOCH FROM (clock_timestamp() - t1)) * 1000.0;
    did_compact := c_rid IS NOT NULL;
    elapsed_ms := (EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0)::float8;
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

-- ---- 0.1.2 bounded maintenance ----

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


-- ==== 0.1.3 scalability overlay ====
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


-- ==== 0.1.4 correctness + sharding overlay ====

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

GRANT EXECUTE ON FUNCTION tci.seal_bounded(regclass, int, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.compact_pairwise(regclass, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.shard_stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO PUBLIC;
REVOKE ALL ON FUNCTION tci.rebuild(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.rebuild(regclass) TO PUBLIC;
REVOKE ALL ON FUNCTION tci.invalidate(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.invalidate(regclass) TO PUBLIC;


-- ==== 0.1.5 run-budget overlay ====
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

-- Non-blocking acquire of every shard lock (same keyspace as rebuild/seal_bounded).
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

-- ==== 0.1.6 seal DELETE pipeline (PK ANY) + routing migration stamp ====
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

-- ==== 0.1.7 fused count_at ====
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

-- ==== 0.1.8 production hardening overlay ====
-- pg_tci 0.1.7 → 0.1.8
-- Production hardening: admin EXECUTE ACL, grant helpers, health/maint history,
-- create() auto-grants admin EXECUTE to table owner.

-- ---------------------------------------------------------------------------
-- Admin EXECUTE grant/revoke helpers (defense in depth vs PUBLIC DEFINER invoke)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.admin_procedures()
RETURNS SETOF regprocedure
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.oid::regprocedure
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'tci'
    AND p.proname = ANY (ARRAY[
      'seal', 'seal_bounded', 'compact', 'compact_pairwise', 'compact_budget',
      'maintain', 'invalidate', 'rebuild', 'capacity_reset', 'set_shard_count',
      'maint_history'
    ]);
$$;

CREATE OR REPLACE FUNCTION tci_internal.grant_admin_execute(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  fp regprocedure;
BEGIN
  IF to_regrole(target_role) IS NULL THEN
    RAISE EXCEPTION 'pg_tci: role % does not exist', target_role;
  END IF;
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', fp, target_role);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.revoke_admin_execute(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  fp regprocedure;
BEGIN
  IF to_regrole(target_role) IS NULL THEN
    RAISE EXCEPTION 'pg_tci: role % does not exist', target_role;
  END IF;
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', fp, target_role);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci.grant_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: grant_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.grant_admin_execute(target_role);
  -- Also allow bootstrap create for that role.
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO %I',
    target_role);
END;
$$;

CREATE OR REPLACE FUNCTION tci.revoke_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: revoke_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.revoke_admin_execute(target_role);
  EXECUTE format(
    'REVOKE ALL ON FUNCTION tci.create(regclass, name, name, int, int, name, int) FROM %I',
    target_role);
END;
$$;

REVOKE ALL ON FUNCTION tci_internal.admin_procedures() FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.grant_admin_execute(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.revoke_admin_execute(name) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- create(): after rebuild, grant admin EXECUTE to table owner
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create(
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
  owner_name name;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
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

  -- Owner can maintain without PUBLIC EXECUTE on admin DEFINER APIs.
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Monitoring: health + maint_history
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.health(source_table regclass)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  published boolean,
  valid boolean,
  shard_count int,
  generation bigint,
  n_tail bigint,
  live_runs int,
  deltas_sealed bigint,
  deltas_sealed_per_sec double precision,
  deltas_ingested bigint,
  deltas_ingested_per_sec double precision,
  last_seal_at timestamptz,
  seconds_since_reset double precision,
  capacity_ok boolean,
  detail text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);
  -- Inline insert (not ensure_cap SQL fn) so CCI makes the row visible to
  -- RETURN QUERY in this same PL/pgSQL call.
  INSERT INTO tci_internal.cap_counters(index_id)
  SELECT idx.index_id
   WHERE NOT EXISTS (
     SELECT 1 FROM tci_internal.cap_counters c WHERE c.index_id = idx.index_id
   );

  RETURN QUERY
  SELECT
    i.index_id,
    format('%I.%I', i.source_nsp, i.source_rel)::text,
    i.published,
    i.valid,
    i.shard_count,
    i.generation,
    (SELECT count(*) FROM tci_internal.tail t
      WHERE t.index_id = i.index_id AND t.generation = i.generation),
    (SELECT count(*)::int FROM tci_internal.runs r
      WHERE r.index_id = i.index_id AND r.status = 'live'),
    c.deltas_sealed,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_sealed / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.deltas_ingested,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_ingested / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.last_seal_at,
    EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at))::float8,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN false
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
           AND EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 60
           AND (c.deltas_sealed / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1))
               < (c.deltas_ingested / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1)) * 0.5
        THEN false
      ELSE true
    END,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN 'invalid_or_unpublished'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
        THEN 'tail_large'::text
      ELSE NULL::text
    END
  FROM tci_internal.indexes i
  JOIN tci_internal.cap_counters c ON c.index_id = i.index_id
  WHERE i.index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.maint_history(
  source_table regclass,
  max_rows int DEFAULT 20
)
RETURNS TABLE (
  id bigint,
  op text,
  started_at timestamptz,
  duration_ms double precision,
  n_tail_before bigint,
  n_tail_after bigint,
  n_live_before int,
  n_live_after int,
  skipped_reason text,
  detail text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  lim int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  lim := GREATEST(COALESCE(max_rows, 20), 1);
  lim := LEAST(lim, 1000);

  RETURN QUERY
  SELECT m.id, m.op, m.started_at, m.duration_ms,
         m.n_tail_before, m.n_tail_after, m.n_live_before, m.n_live_after,
         m.skipped_reason, m.detail
  FROM tci_internal.maint_log m
  WHERE m.index_id = idx.index_id
  ORDER BY m.id DESC
  LIMIT lim;
END;
$$;

-- ---------------------------------------------------------------------------
-- Harden: revoke PUBLIC EXECUTE on admin DEFINER APIs (keep create for bootstrap)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  fp regprocedure;
BEGIN
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', fp);
  END LOOP;
END $$;

-- Read-path stays PUBLIC + require_select
GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.shard_stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.health(regclass) TO PUBLIC;

-- create remains PUBLIC for owner bootstrap (gated by require_admin)
GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO PUBLIC;

-- grant/revoke_admin: no PUBLIC; superuser/db owner only via body check
REVOKE ALL ON FUNCTION tci.grant_admin(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.revoke_admin(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maint_history(regclass, int) FROM PUBLIC;

COMMENT ON FUNCTION tci.grant_admin(name) IS
  'Grant EXECUTE on TCI admin APIs to a role (superuser/db owner).';
COMMENT ON FUNCTION tci.health(regclass) IS
  'Per-index capacity/health snapshot for monitoring.';
COMMENT ON FUNCTION tci.maint_history(regclass, int) IS
  'Recent seal/compact/maintain log rows for an index (admin).';

-- Existing indexes: grant admin EXECUTE to current table owners after revoke.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT roles.rolname AS rolname
    FROM tci_internal.indexes i
    JOIN pg_class c ON c.oid = i.source_oid
    JOIN pg_roles roles ON roles.oid = c.relowner
  LOOP
    PERFORM tci_internal.grant_admin_execute(r.rolname);
  END LOOP;
END $$;

-- ==== 0.1.9 native filtered + hardening ====
-- pg_tci 0.1.8 → 0.1.9
-- Native filtered temporal coverage: partial TCI instances per equality filter.
-- Does NOT change TCIP v1, Packed IAR layout, or unfiltered count_at semantics.
-- No slice tables; deltas captured from the source table trigger.

-- ---------------------------------------------------------------------------
-- Catalog: allow multiple indexes per source (one unfiltered + N filtered)
-- ---------------------------------------------------------------------------
ALTER TABLE tci_internal.indexes
  DROP CONSTRAINT IF EXISTS indexes_source_oid_key;

ALTER TABLE tci_internal.indexes
  ADD COLUMN IF NOT EXISTS filter_col name,
  ADD COLUMN IF NOT EXISTS filter_value text,
  ADD COLUMN IF NOT EXISTS filter_typid oid,
  ADD COLUMN IF NOT EXISTS filter_is_null boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN tci_internal.indexes.filter_col IS
  'NULL = unfiltered index; else single-column equality filter column';
COMMENT ON COLUMN tci_internal.indexes.filter_value IS
  'Canonical text of equality value (cast via filter_typid); unused when filter_is_null';
COMMENT ON COLUMN tci_internal.indexes.filter_is_null IS
  'When true, this filtered index matches rows where filter_col IS NULL';

-- Exactly one unfiltered index per source OID
CREATE UNIQUE INDEX IF NOT EXISTS indexes_unfiltered_source_uidx
  ON tci_internal.indexes (source_oid)
  WHERE filter_col IS NULL;

-- Exactly one filtered index per (source, column, value|NULL)
CREATE UNIQUE INDEX IF NOT EXISTS indexes_filtered_source_uidx
  ON tci_internal.indexes (
    source_oid,
    filter_col,
    filter_is_null,
    COALESCE(filter_value, '')
  )
  WHERE filter_col IS NOT NULL;

CREATE INDEX IF NOT EXISTS indexes_filter_lookup_idx
  ON tci_internal.indexes (source_oid, filter_col, filter_is_null, filter_value)
  WHERE filter_col IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Type-safe filter value resolution (no dynamic SQL injection of values)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.supported_filter_type(typid oid)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT typid IN (
    'text'::regtype::oid,
    'varchar'::regtype::oid,
    'bpchar'::regtype::oid,
    'int4'::regtype::oid,
    'int8'::regtype::oid,
    'int2'::regtype::oid
  )
  OR EXISTS (
    SELECT 1 FROM pg_type t
    WHERE t.oid = typid AND t.typtype = 'e'
  );
$$;

-- Resolve user-supplied text to (typid, canonical text, is_null).
-- p_filter_value NULL => match IS NULL (filter_is_null=true).
CREATE OR REPLACE FUNCTION tci_internal.resolve_filter_value(
  p_source regclass,
  p_filter_col name,
  p_filter_value text,
  OUT o_typid oid,
  OUT o_canon text,
  OUT o_is_null boolean
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  att_ty oid;
  typname text;
  q text;
BEGIN
  SELECT a.atttypid INTO att_ty
  FROM pg_attribute a
  WHERE a.attrelid = p_source
    AND a.attname = p_filter_col
    AND NOT a.attisdropped
    AND a.attnum > 0;
  IF att_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: filter column % not found on %',
      p_filter_col, p_source;
  END IF;
  IF NOT tci_internal.supported_filter_type(att_ty) THEN
    RAISE EXCEPTION
      'pg_tci: filter column % type % not supported (text/varchar/int/bigint/enum)',
      p_filter_col, att_ty::regtype;
  END IF;

  o_typid := att_ty;
  IF p_filter_value IS NULL THEN
    o_canon := NULL;
    o_is_null := true;
    RETURN;
  END IF;

  o_is_null := false;
  typname := format_type(att_ty, NULL);
  -- Bind as text, cast to real column type, emit canonical text.
  -- Uses typed parameter — never interpolates the value into SQL text.
  q := format('SELECT ($1::text)::%s::text', typname);
  BEGIN
    EXECUTE q INTO o_canon USING p_filter_value;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION
      'pg_tci: filter_value % is not a valid literal for type %',
      p_filter_value, att_ty::regtype
      USING ERRCODE = '22P02';
  END;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.native_count_filtered(
  p_source regclass,
  p_start name,
  p_end name,
  p_filter_col name,
  p_typid oid,
  p_canon text,
  p_is_null boolean,
  p_ts timestamptz
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v bigint;
  q text;
  typname text := format_type(p_typid, NULL);
BEGIN
  IF p_is_null THEN
    q := format(
      'SELECT count(*)::bigint FROM %s s
        WHERE s.%I IS NULL
          AND s.%I <= $1
          AND (s.%I IS NULL OR s.%I > $1)',
      p_source, p_filter_col, p_start, p_end, p_end);
    EXECUTE q INTO v USING p_ts;
  ELSE
    q := format(
      'SELECT count(*)::bigint FROM %s s
        WHERE s.%I IS NOT DISTINCT FROM ($2::text)::%s
          AND s.%I <= $1
          AND (s.%I IS NULL OR s.%I > $1)',
      p_source, p_filter_col, typname, p_start, p_end, p_end);
    EXECUTE q INTO v USING p_ts, p_canon;
  END IF;
  RETURN v;
END;
$$;

-- Row filter value as canonical text (NULL => SQL NULL)
CREATE OR REPLACE FUNCTION tci_internal.row_filter_canon(
  p_row record,
  p_filter_col name,
  p_typid oid
) RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  typname text := format_type(p_typid, NULL);
  v text;
BEGIN
  EXECUTE format('SELECT (($1).%I)::%s::text', p_filter_col, typname)
    INTO v USING p_row;
  RETURN v;
END;
$$;

-- ---------------------------------------------------------------------------
-- Lookups: unfiltered vs filtered (never confuse the two)
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
  -- Prefer exact OID match on the UNFILTERED index only
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = source_table
    AND filter_col IS NULL;
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
    AND filter_col IS NULL
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: no index for % — call tci.create first', source_table;
  END IF;

  SELECT count(*) INTO conflict
  FROM tci_internal.indexes i
  WHERE i.index_id <> idx.index_id
    AND i.source_oid = source_table
    AND i.filter_col IS NULL;
  IF conflict > 0 THEN
    RAISE EXCEPTION
      'pg_tci: refusing relink — OID % already bound to another unfiltered index',
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

  -- Also rebind filtered indexes that share the same nsp/rel name
  UPDATE tci_internal.indexes
     SET source_oid = new_oid,
         valid = false,
         published = false,
         notes = coalesce(notes, '') || format(
           ' [relink oid %s — invalidated pending rebuild]', clock_timestamp())
   WHERE source_nsp = nsp AND source_rel = rel
     AND filter_col IS NOT NULL
     AND source_oid IS DISTINCT FROM new_oid;

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

CREATE OR REPLACE FUNCTION tci_internal.relink_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS tci_internal.indexes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  typid oid;
  canon text;
  is_null boolean;
  nsp name;
  rel name;
  start_ty oid;
  end_ty oid;
  fty oid;
BEGIN
  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  -- Prefer OID match
  SELECT * INTO idx
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column
    AND i.filter_is_null = is_null
    AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon);

  -- Dump/restore: OID changed under same nsp/rel — rebind all matching filters
  IF NOT FOUND THEN
    SELECT * INTO idx
    FROM tci_internal.indexes i
    WHERE i.source_nsp = nsp AND i.source_rel = rel
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION
        'pg_tci: no filtered index for %(%=%) — call tci.create_filtered first',
        source_table, filter_column,
        CASE WHEN is_null THEN 'NULL' ELSE canon END;
    END IF;
    UPDATE tci_internal.indexes
       SET source_oid = source_table,
           valid = false,
           published = false,
           notes = coalesce(notes, '') || format(
             ' [relink oid %s — invalidated pending rebuild_filtered]', clock_timestamp())
     WHERE source_nsp = nsp AND source_rel = rel
       AND filter_col IS NOT NULL
       AND source_oid IS DISTINCT FROM source_table;
    SELECT * INTO idx FROM tci_internal.indexes WHERE index_id = idx.index_id;
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger
      WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
         FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
        source_table);
    END IF;
    RETURN idx;  -- invalid until rebuild_filtered (fail closed, no stale packed)
  END IF;

  IF nsp IS DISTINCT FROM idx.source_nsp OR rel IS DISTINCT FROM idx.source_rel THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [oid/name mismatch %s]', clock_timestamp())
     WHERE index_id = idx.index_id
     RETURNING * INTO idx;
    RAISE EXCEPTION
      'pg_tci: filtered source_oid % no longer matches cataloged % . %',
      source_table, idx.source_nsp, idx.source_rel;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO fty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.filter_col AND NOT a.attisdropped;

  IF start_ty IS NULL OR end_ty IS NULL OR fty IS NULL
     OR start_ty <> 'timestamptz'::regtype
     OR end_ty <> 'timestamptz'::regtype
     OR fty IS DISTINCT FROM idx.filter_typid THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [filter col type/missing %s]', clock_timestamp())
     WHERE index_id = idx.index_id;
    RAISE EXCEPTION
      'pg_tci: filtered index columns on % missing or type-changed — fail closed',
      source_table;
  END IF;

  RETURN idx;
END;
$$;

-- ---------------------------------------------------------------------------
-- event_rows: honor filter predicate for rebuild of filtered indexes
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.event_rows(p_index_id int)
RETURNS TABLE(ts timestamptz, delta smallint)
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  q text;
  typname text;
BEGIN
  SELECT * INTO STRICT idx FROM tci_internal.indexes WHERE index_id = p_index_id;

  IF idx.filter_col IS NULL THEN
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s WHERE s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.end_col);
    RETURN QUERY EXECUTE q;
  ELSIF idx.filter_is_null THEN
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s WHERE s.%I IS NULL
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s
         WHERE s.%I IS NULL AND s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel, idx.filter_col,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.filter_col, idx.end_col);
    RETURN QUERY EXECUTE q;
  ELSE
    typname := format_type(idx.filter_typid, NULL);
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s
         WHERE s.%I IS NOT DISTINCT FROM ($1::text)::%s
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s
         WHERE s.%I IS NOT DISTINCT FROM ($1::text)::%s
           AND s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel, idx.filter_col, typname,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.filter_col, typname,
      idx.end_col);
    RETURN QUERY EXECUTE q USING idx.filter_value;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Tail helpers for trigger (interval ±1 on one index)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.tail_add_interval(
  p_idx tci_internal.indexes,
  p_id bigint,
  p_start timestamptz,
  p_end timestamptz,
  p_sign smallint   -- +1 contribute, -1 remove
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  sid int;
BEGIN
  IF NOT p_idx.published OR NOT p_idx.valid THEN
    RETURN;
  END IF;
  IF p_idx.shard_count > 1 AND p_id IS NULL THEN
    RAISE EXCEPTION 'pg_tci: NULL % not allowed for sharded index', p_idx.id_col;
  END IF;
  sid := tci_internal.row_shard_v1(p_idx.shard_count, p_id);
  INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
  VALUES (p_idx.index_id, p_idx.generation, sid, p_start, p_sign);
  IF p_end IS NOT NULL THEN
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_end, (-p_sign)::smallint);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.tail_adjust_bounds(
  p_idx tci_internal.indexes,
  p_id bigint,
  p_start_old timestamptz,
  p_end_old timestamptz,
  p_start_new timestamptz,
  p_end_new timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  sid int;
BEGIN
  IF NOT p_idx.published OR NOT p_idx.valid THEN
    RETURN;
  END IF;
  IF p_start_old IS NOT DISTINCT FROM p_start_new
     AND p_end_old IS NOT DISTINCT FROM p_end_new THEN
    RETURN;
  END IF;
  sid := tci_internal.row_shard_v1(p_idx.shard_count, p_id);

  IF p_start_old IS DISTINCT FROM p_start_new THEN
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_start_old, -1);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_start_new, 1);
  END IF;

  IF p_end_old IS DISTINCT FROM p_end_new THEN
    IF p_end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (p_idx.index_id, p_idx.generation, sid, p_end_old, 1);
    END IF;
    IF p_end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (p_idx.index_id, p_idx.generation, sid, p_end_new, -1);
    END IF;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Trigger: unfiltered + filtered routing (cost ~ #distinct filter columns)
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
  id_old bigint;
  id_new bigint;
  fcol name;
  canon_old text;
  canon_new text;
  null_old boolean;
  null_new boolean;
  has_filtered boolean;
BEGIN
  -- ---- Unfiltered index (0 or 1) ----
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID
    AND filter_col IS NULL
  FOR KEY SHARE;

  IF FOUND AND idx.published AND idx.valid THEN
    IF TG_OP = 'INSERT' THEN
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_new, start_new, end_new USING NEW;
      PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
    ELSIF TG_OP = 'DELETE' THEN
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_old, start_old, end_old USING OLD;
      PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
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
      PERFORM tci_internal.tail_adjust_bounds(
        idx, id_old, start_old, end_old, start_new, end_new);
    END IF;
  END IF;

  -- ---- Filtered indexes ----
  SELECT EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = TG_RELID AND filter_col IS NOT NULL
  ) INTO has_filtered;

  IF NOT has_filtered THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  -- Use id/start/end from first filtered catalog row (same source columns).
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID AND filter_col IS NOT NULL
  LIMIT 1;

  IF TG_OP = 'INSERT' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
  ELSE
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
  END IF;

  FOR fcol IN
    SELECT DISTINCT i.filter_col
    FROM tci_internal.indexes i
    WHERE i.source_oid = TG_RELID
      AND i.filter_col IS NOT NULL
  LOOP
    -- Resolve OLD/NEW filter canons for this column (type from any matching index)
    SELECT i.filter_typid INTO idx.filter_typid
    FROM tci_internal.indexes i
    WHERE i.source_oid = TG_RELID AND i.filter_col = fcol
    LIMIT 1;

    IF TG_OP = 'INSERT' THEN
      canon_new := tci_internal.row_filter_canon(NEW, fcol, idx.filter_typid);
      null_new := (canon_new IS NULL);
      FOR idx IN
        SELECT * FROM tci_internal.indexes i
        WHERE i.source_oid = TG_RELID
          AND i.filter_col = fcol
          AND i.filter_is_null = null_new
          AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
        FOR KEY SHARE
      LOOP
        PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
      END LOOP;

    ELSIF TG_OP = 'DELETE' THEN
      canon_old := tci_internal.row_filter_canon(OLD, fcol, idx.filter_typid);
      null_old := (canon_old IS NULL);
      FOR idx IN
        SELECT * FROM tci_internal.indexes i
        WHERE i.source_oid = TG_RELID
          AND i.filter_col = fcol
          AND i.filter_is_null = null_old
          AND (null_old OR i.filter_value IS NOT DISTINCT FROM canon_old)
        FOR KEY SHARE
      LOOP
        PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
      END LOOP;

    ELSIF TG_OP = 'UPDATE' THEN
      canon_old := tci_internal.row_filter_canon(OLD, fcol, idx.filter_typid);
      canon_new := tci_internal.row_filter_canon(NEW, fcol, idx.filter_typid);
      null_old := (canon_old IS NULL);
      null_new := (canon_new IS NULL);

      IF null_old IS DISTINCT FROM null_new
         OR canon_old IS DISTINCT FROM canon_new THEN
        -- Filter value moved: remove from old bucket, add to new
        FOR idx IN
          SELECT * FROM tci_internal.indexes i
          WHERE i.source_oid = TG_RELID
            AND i.filter_col = fcol
            AND i.filter_is_null = null_old
            AND (null_old OR i.filter_value IS NOT DISTINCT FROM canon_old)
          FOR KEY SHARE
        LOOP
          PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
        END LOOP;
        FOR idx IN
          SELECT * FROM tci_internal.indexes i
          WHERE i.source_oid = TG_RELID
            AND i.filter_col = fcol
            AND i.filter_is_null = null_new
            AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
          FOR KEY SHARE
        LOOP
          PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
        END LOOP;
      ELSE
        -- Same filter bucket: only adjust if interval bounds changed
        IF start_old IS DISTINCT FROM start_new
           OR end_old IS DISTINCT FROM end_new THEN
          FOR idx IN
            SELECT * FROM tci_internal.indexes i
            WHERE i.source_oid = TG_RELID
              AND i.filter_col = fcol
              AND i.filter_is_null = null_new
              AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
            FOR KEY SHARE
          LOOP
            PERFORM tci_internal.tail_adjust_bounds(
              idx, id_new, start_old, end_old, start_new, end_new);
          END LOOP;
        END IF;
      END IF;
    END IF;
  END LOOP;

  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- create(): uniqueness is unfiltered-only
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create(
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
  owner_name name;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
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

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = source_table AND filter_col IS NULL
  ) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_nsp = nsp AND source_rel = rel AND filter_col IS NULL
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

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild(source_table);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Public filtered API
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create_filtered(
  source_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,
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
  owner_name name;
  typid oid;
  canon text;
  is_null boolean;
  -- inherit start/end from existing unfiltered if present
  base tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;
  IF chunk_bytes NOT IN (4096, 8192, 16384, 32768) THEN
    RAISE EXCEPTION 'pg_tci: chunk_bytes must be 4096|8192|16384|32768';
  END IF;
  IF cp_interval NOT IN (32, 64, 128) THEN
    RAISE EXCEPTION 'pg_tci: cp_interval must be 32|64|128';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_column, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF filter_column IN (start_column, end_column, id_col) THEN
    RAISE EXCEPTION 'pg_tci: filter_column must be distinct from start/end/id columns';
  END IF;

  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  -- If an unfiltered index exists, require matching interval columns
  SELECT * INTO base
  FROM tci_internal.indexes
  WHERE source_oid = source_table AND filter_col IS NULL;
  IF FOUND THEN
    IF base.start_col IS DISTINCT FROM start_column
       OR base.end_col IS DISTINCT FROM end_column THEN
      RAISE EXCEPTION
        'pg_tci: filtered start/end must match existing unfiltered index (% / %)',
        base.start_col, base.end_col;
    END IF;
    IF base.id_col IS DISTINCT FROM id_col THEN
      RAISE EXCEPTION
        'pg_tci: filtered id_col must match existing unfiltered index (%)',
        base.id_col;
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
  ) THEN
    RAISE EXCEPTION 'pg_tci: filtered index already exists for %(%=%)',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid,
    filter_col, filter_value, filter_typid, filter_is_null)
  VALUES (
    source_table, nsp, rel, start_column, end_column,
    chunk_bytes, cp_interval, id_col, shard_count, false, true,
    filter_column, canon, typid, is_null)
  RETURNING index_id INTO idx_id;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered(
  source_table regclass,
  as_of timestamptz,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  typid oid;
  canon text;
  is_null boolean;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT * INTO idx
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column
    AND i.filter_is_null = is_null
    AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon);

  IF NOT FOUND THEN
    -- Never silently use another filter or the unfiltered index.
    RAISE EXCEPTION
      'pg_tci: no filtered index for %(%=%) — create_filtered or use native COUNT',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END
      USING ERRCODE = 'P0002';
  END IF;

  -- Identity / type sanity (fail closed)
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count_filtered(
      source_table, idx.start_col, idx.end_col,
      idx.filter_col, idx.filter_typid, idx.filter_value, idx.filter_is_null,
      as_of);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, as_of)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, as_of);
END;
$$;

CREATE OR REPLACE FUNCTION tci.rebuild_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
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
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

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
         notes = coalesce(notes, '') || format(
           ' [rebuild_filtered %s n=%s]', clock_timestamp(), n)
   WHERE index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.drop_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  DELETE FROM tci_internal.indexes WHERE index_id = idx.index_id;

  -- Drop shared trigger only when no indexes remain for this source
  IF NOT EXISTS (
    SELECT 1 FROM tci_internal.indexes WHERE source_oid = source_table
  ) THEN
    EXECUTE format('DROP TRIGGER IF EXISTS tci_source_trig ON %s', source_table);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci.invalidate_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  UPDATE tci_internal.indexes
     SET valid = false,
         published = false,
         notes = coalesce(notes, '') || format(' [invalidated_filtered %s]', clock_timestamp())
   WHERE index_id = idx.index_id;
END;
$$;

-- Seal one filtered index (batch-ID exact-once; safe under concurrent writers)
DROP FUNCTION IF EXISTS tci.seal_filtered(regclass, name, text);
CREATE OR REPLACE FUNCTION tci.seal_filtered(
  source_table regclass,
  filter_column name,
  filter_value text,
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
  n_src bigint;
  got_lock boolean;
  batch_ids bigint[];
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;

  got_lock := tci_internal.try_all_shard_locks(idx.index_id, idx.shard_count);
  IF NOT got_lock THEN
    RETURN NULL;
  END IF;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: filtered index for % is not published/valid', source_table;
  END IF;

  IF to_regclass('pg_temp._tci_batch') IS NOT NULL THEN
    DROP TABLE _tci_batch;
  END IF;
  -- Lock a finite batch of tail row IDs so concurrent inserts are not deleted
  -- without being packed (same exact-once pattern as seal_bounded).
  CREATE TEMP TABLE _tci_batch ON COMMIT DROP AS
  SELECT t.id, t.ts, t.delta
  FROM tci_internal.tail t
  WHERE t.index_id = idx.index_id
    AND t.generation = idx.generation
  ORDER BY t.id
  LIMIT max_rows
  FOR UPDATE OF t SKIP LOCKED;

  SELECT count(*) INTO n_src FROM _tci_batch;
  IF n_src = 0 THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(id) INTO batch_ids FROM _tci_batch;

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
    DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, 0)
  RETURNING run_id INTO rid;
  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);

  RETURN rid;
END;
$$;

CREATE OR REPLACE FUNCTION tci.compact_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  -- Reuse pairwise compact via temporarily routing through source-only API
  -- is unsafe (would hit unfiltered). Inline minimal pairwise for this index_id.
  RETURN tci_internal.compact_pairwise_index(idx.index_id, idx.shard_count);
END;
$$;

-- Minimal pairwise compact by index_id (shared by filtered maintain)
CREATE OR REPLACE FUNCTION tci_internal.compact_pairwise_index(
  p_index_id int,
  p_shard_count int
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r1 record;
  r2 record;
  rid bigint;
  n int;
  got_lock boolean;
  cb int;
  cp int;
BEGIN
  got_lock := tci_internal.try_all_shard_locks(p_index_id, p_shard_count);
  IF NOT got_lock THEN
    RETURN NULL;
  END IF;

  SELECT run_id, n_entries INTO r1
  FROM tci_internal.runs
  WHERE index_id = p_index_id AND status = 'live'
  ORDER BY run_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT run_id, n_entries INTO r2
  FROM tci_internal.runs
  WHERE index_id = p_index_id AND status = 'live' AND run_id > r1.run_id
  ORDER BY run_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT chunk_bytes, cp_interval INTO cb, cp
  FROM tci_internal.indexes WHERE index_id = p_index_id;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;

  -- Merge two live runs: unpack → coalesce by ts_us → rebuild prefix table.
  -- Timestamps are µs since PostgreSQL epoch 2000-01-01 (TCIP v1).
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  WITH entries AS (
    SELECT e.ts_us, e.delta::bigint AS delta
    FROM tci_internal.runs r
    JOIN tci_internal.chunks c ON c.index_id = r.index_id AND c.run_id = r.run_id
    CROSS JOIN LATERAL tci_internal.unpack_entries(c.payload) e
    WHERE r.index_id = p_index_id
      AND r.run_id IN (r1.run_id, r2.run_id)
      AND r.status = 'live'
  ),
  merged AS (
    SELECT ts_us, sum(delta)::bigint AS delta
    FROM entries
    GROUP BY ts_us
    HAVING sum(delta) <> 0
  )
  SELECT row_number() OVER (ORDER BY ts_us) AS rn,
         (TIMESTAMPTZ '2000-01-01 00:00:00+00'
            + (ts_us * INTERVAL '1 microsecond')) AS ts,
         ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts_us)::bigint AS prefix_sum
  FROM merged;

  SELECT count(*) INTO n FROM _tci_pref;
  IF n = 0 THEN
    DELETE FROM tci_internal.chunks
     WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
    DELETE FROM tci_internal.runs
     WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (p_index_id, 'live', n, cb, cp, 0)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(p_index_id, rid, cb, cp);

  DELETE FROM tci_internal.chunks
   WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
  DELETE FROM tci_internal.runs
   WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);

  RETURN rid;
END;
$$;

-- Round-robin maintain across all filtered indexes on a source table
CREATE OR REPLACE FUNCTION tci.maintain_filters(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8
) RETURNS TABLE (
  index_id int,
  filter_col name,
  filter_value text,
  sealed bigint,
  compacted bigint,
  n_tail bigint,
  live_runs int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  n_tail_cur bigint;
  n_live int;
  s_rid bigint;
  c_rid bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);

  FOR idx IN
    SELECT i.* FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col IS NOT NULL
      AND i.published AND i.valid
    ORDER BY i.index_id
  LOOP
    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    s_rid := NULL;
    c_rid := NULL;
    IF n_tail_cur >= tail_target THEN
      s_rid := tci.seal_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END,
        GREATEST(tail_target, 8192));
    END IF;
    IF n_live >= max_live_runs THEN
      c_rid := tci.compact_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END);
    END IF;

    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    index_id := idx.index_id;
    filter_col := idx.filter_col;
    filter_value := idx.filter_value;
    sealed := s_rid;
    compacted := c_rid;
    n_tail := n_tail_cur;
    live_runs := n_live;
    RETURN NEXT;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci.list_filters(source_table regclass)
RETURNS TABLE (
  index_id int,
  filter_col name,
  filter_value text,
  filter_is_null boolean,
  published boolean,
  valid boolean,
  generation bigint,
  n_tail bigint,
  live_runs int
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.require_select(source_table);
  RETURN QUERY
  SELECT i.index_id, i.filter_col, i.filter_value, i.filter_is_null,
         i.published, i.valid, i.generation,
         (SELECT count(*) FROM tci_internal.tail t
           WHERE t.index_id = i.index_id AND t.generation = i.generation),
         (SELECT count(*)::int FROM tci_internal.runs r
           WHERE r.index_id = i.index_id AND r.status = 'live')
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col IS NOT NULL
  ORDER BY i.filter_col, i.filter_is_null, i.filter_value;
END;
$$;

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.admin_procedures()
RETURNS SETOF regprocedure
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.oid::regprocedure
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'tci'
    AND p.proname = ANY (ARRAY[
      'seal', 'seal_bounded', 'compact', 'compact_pairwise', 'compact_budget',
      'maintain', 'invalidate', 'rebuild', 'capacity_reset', 'set_shard_count',
      'maint_history',
      'rebuild_filtered', 'drop_filtered', 'invalidate_filtered',
      'seal_filtered', 'compact_filtered', 'maintain_filters'
    ]);
$$;

-- create_filtered stays PUBLIC for owner bootstrap (like tci.create)
GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.list_filters(regclass) TO PUBLIC;

REVOKE ALL ON FUNCTION tci.rebuild_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.drop_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.invalidate_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.seal_filtered(regclass, name, text, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.compact_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maintain_filters(regclass, int, int) FROM PUBLIC;

-- Re-grant admin EXECUTE to current table owners (includes new filtered admin APIs)
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT roles.rolname AS rolname
    FROM tci_internal.indexes i
    JOIN pg_class c ON c.oid = i.source_oid
    JOIN pg_roles roles ON roles.oid = c.relowner
  LOOP
    PERFORM tci_internal.grant_admin_execute(r.rolname);
  END LOOP;
END $$;

COMMENT ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) IS
  'Create a partial TCI for single-column equality filter (no row copies).';
COMMENT ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) IS
  'Exact filtered interval COUNT via registered partial TCI; errors if unregistered.';
COMMENT ON FUNCTION tci.maintain_filters(regclass, int, int) IS
  'Seal/compact all filtered TCI instances on a source table.';

COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.9 — native filtered coverage)';

-- grant_admin / revoke_admin: include create_filtered bootstrap grant
CREATE OR REPLACE FUNCTION tci.grant_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: grant_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.grant_admin_execute(target_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO %I',
    target_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO %I',
    target_role);
END;
$$;

CREATE OR REPLACE FUNCTION tci.revoke_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: revoke_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.revoke_admin_execute(target_role);
  EXECUTE format(
    'REVOKE ALL ON FUNCTION tci.create(regclass, name, name, int, int, name, int) FROM %I',
    target_role);
  EXECUTE format(
    'REVOKE ALL ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) FROM %I',
    target_role);
END;
$$;

-- ===========================================================================
-- 0.1.9 hardening: RLS fail-closed, reject partitions, storage accounting
-- ===========================================================================

CREATE OR REPLACE FUNCTION tci_internal.require_plain_heap(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  kind "char";
  ispart boolean;
BEGIN
  SELECT c.relkind, c.relispartition
    INTO kind, ispart
  FROM pg_class c WHERE c.oid = p_source;
  IF kind IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', p_source;
  END IF;
  IF kind = 'p' OR ispart THEN
    RAISE EXCEPTION
      'pg_tci: partitioned tables are not supported (source %)', p_source
      USING ERRCODE = '0A000';
  END IF;
  IF kind <> 'r' THEN
    RAISE EXCEPTION
      'pg_tci: source must be a plain heap table (got relkind %)', kind;
  END IF;
END;
$$;

-- SECURITY DEFINER COUNT reads packed aggregates, not the source heap.
-- SELECT privilege alone must not authorize bypassing RLS.
CREATE OR REPLACE FUNCTION tci_internal.require_rls_ok(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  rls boolean;
  force_rls boolean;
  owner oid;
BEGIN
  SELECT c.relrowsecurity, c.relforcerowsecurity, c.relowner
    INTO rls, force_rls, owner
  FROM pg_class c WHERE c.oid = p_source;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', p_source;
  END IF;
  IF NOT COALESCE(rls, false) THEN
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolbypassrls
  ) THEN
    RETURN;
  END IF;
  -- Owner bypasses RLS unless FORCE ROW LEVEL SECURITY
  IF NOT COALESCE(force_rls, false)
     AND pg_has_role(session_user, owner, 'MEMBER') THEN
    RETURN;
  END IF;
  RAISE EXCEPTION
    'pg_tci: RLS is enabled on % — TCI COUNT refused (fail closed; aggregates bypass row policies)',
    p_source
    USING ERRCODE = '42501';
END;
$$;

REVOKE ALL ON FUNCTION tci_internal.require_plain_heap(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.require_rls_ok(regclass) FROM PUBLIC;

-- Patch create() — reject partitions
CREATE OR REPLACE FUNCTION tci.create(
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
  owner_name name;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  PERFORM tci_internal.require_plain_heap(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
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

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = source_table AND filter_col IS NULL
  ) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_nsp = nsp AND source_rel = rel AND filter_col IS NULL
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

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild(source_table);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.create_filtered(
  source_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,
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
  owner_name name;
  typid oid;
  canon text;
  is_null boolean;
  base tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  PERFORM tci_internal.require_plain_heap(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;
  IF chunk_bytes NOT IN (4096, 8192, 16384, 32768) THEN
    RAISE EXCEPTION 'pg_tci: chunk_bytes must be 4096|8192|16384|32768';
  END IF;
  IF cp_interval NOT IN (32, 64, 128) THEN
    RAISE EXCEPTION 'pg_tci: cp_interval must be 32|64|128';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_column, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF filter_column IN (start_column, end_column, id_col) THEN
    RAISE EXCEPTION 'pg_tci: filter_column must be distinct from start/end/id columns';
  END IF;

  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT * INTO base
  FROM tci_internal.indexes
  WHERE source_oid = source_table AND filter_col IS NULL;
  IF FOUND THEN
    IF base.start_col IS DISTINCT FROM start_column
       OR base.end_col IS DISTINCT FROM end_column THEN
      RAISE EXCEPTION
        'pg_tci: filtered start/end must match existing unfiltered index (% / %)',
        base.start_col, base.end_col;
    END IF;
    IF base.id_col IS DISTINCT FROM id_col THEN
      RAISE EXCEPTION
        'pg_tci: filtered id_col must match existing unfiltered index (%)',
        base.id_col;
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
  ) THEN
    RAISE EXCEPTION 'pg_tci: filtered index already exists for %(%=%)',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid,
    filter_col, filter_value, filter_typid, filter_is_null)
  VALUES (
    source_table, nsp, rel, start_column, end_column,
    chunk_bytes, cp_interval, id_col, shard_count, false, true,
    filter_column, canon, typid, is_null)
  RETURNING index_id INTO idx_id;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.grant_admin_execute(owner_name);

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
BEGIN
  PERFORM tci_internal.require_select(source_table);
  PERFORM tci_internal.require_rls_ok(source_table);
  idx := tci_internal.relink_source(source_table);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count(
      source_table, idx.start_col, idx.end_col, ts);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, ts)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, ts);
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered(
  source_table regclass,
  as_of timestamptz,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  PERFORM tci_internal.require_rls_ok(source_table);
  -- relink_filtered resolves OID or nsp/rel (dump/restore) and fail-closes if invalid
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count_filtered(
      source_table, idx.start_col, idx.end_col,
      idx.filter_col, idx.filter_typid, idx.filter_value, idx.filter_is_null,
      as_of);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, as_of)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, as_of);
END;
$$;

GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO PUBLIC;

-- Full storage accounting for all TCI-related relations on a source
CREATE OR REPLACE FUNCTION tci.storage_bytes(source_table regclass)
RETURNS TABLE (
  component text,
  index_id int,
  filter_col name,
  filter_value text,
  bytes bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r record;
  b bigint;
BEGIN
  PERFORM tci_internal.require_select(source_table);

  SELECT pg_total_relation_size(source_table) INTO b;
  component := 'source_table_total'; index_id := NULL;
  filter_col := NULL; filter_value := NULL; bytes := b;
  RETURN NEXT;

  FOR r IN
    SELECT i.index_id, i.filter_col, i.filter_value, i.filter_is_null
    FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
    ORDER BY i.filter_col NULLS FIRST, i.index_id
  LOOP
    SELECT
      COALESCE((SELECT sum(pg_column_size(c.payload))
                FROM tci_internal.chunks c WHERE c.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(t.*))
                  FROM tci_internal.tail t WHERE t.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(rn.*))
                  FROM tci_internal.runs rn WHERE rn.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(ch.*) - pg_column_size(ch.payload))
                  FROM tci_internal.chunks ch WHERE ch.index_id = r.index_id), 0)
      + COALESCE((SELECT pg_column_size(i.*)
                  FROM tci_internal.indexes i WHERE i.index_id = r.index_id), 0)
    INTO b;

    component := 'index_payload_est';
    index_id := r.index_id;
    filter_col := r.filter_col;
    filter_value := CASE WHEN r.filter_is_null THEN NULL ELSE r.filter_value END;
    bytes := COALESCE(b, 0);
    RETURN NEXT;
  END LOOP;

  -- Full tci_internal relation sizes (all indexes in this DB share these heaps)
  FOR r IN
    SELECT c.relname AS nm, pg_total_relation_size(c.oid) AS sz
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'tci_internal'
      AND c.relkind IN ('r', 'i', 't', 'm')
    ORDER BY 1
  LOOP
    component := 'tci_internal.' || r.nm;
    index_id := NULL; filter_col := NULL; filter_value := NULL;
    bytes := r.sz;
    RETURN NEXT;
  END LOOP;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.storage_bytes(regclass) TO PUBLIC;

COMMENT ON FUNCTION tci.storage_bytes(regclass) IS
  'Full storage accounting: source + per-index estimates + all tci_internal relation sizes.';
COMMENT ON FUNCTION tci_internal.require_rls_ok(regclass) IS
  'Fail closed when RLS would be bypassed by SECURITY DEFINER TCI COUNT.';
COMMENT ON FUNCTION tci_internal.require_plain_heap(regclass) IS
  'Reject partitioned / non-heap sources.';

-- ===== 0.1.10 pilot-ops additions (also in 0.1.9--0.1.10.sql) =====
-- pg_tci 0.1.9 → 0.1.10
-- Pilot-ops hardening: rebuild_invalid helpers, maintain_filters relink,
-- filter_fit_estimate, richer health.detail. Bgworker multi-DB is C-only
-- (shared_preload GUCs; no SQL change required for worker).

-- ---------------------------------------------------------------------------
-- list_invalid / rebuild_invalid
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.list_invalid(
  source_table regclass DEFAULT NULL
)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  filter_col name,
  filter_value text,
  filter_is_null boolean,
  published boolean,
  valid boolean,
  notes text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF source_table IS NOT NULL THEN
    PERFORM tci_internal.require_select(source_table);
  END IF;

  RETURN QUERY
  SELECT i.index_id,
         format('%I.%I', i.source_nsp, i.source_rel)::text,
         i.filter_col,
         i.filter_value,
         i.filter_is_null,
         i.published,
         i.valid,
         i.notes
    FROM tci_internal.indexes i
   WHERE (NOT i.valid OR NOT i.published)
     AND (
       source_table IS NULL
       OR i.source_oid = source_table
       OR (i.source_nsp, i.source_rel) = (
            SELECT c.relnamespace::regnamespace::name, c.relname
              FROM pg_class c WHERE c.oid = source_table)
     )
   ORDER BY i.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.rebuild_invalid(
  source_table regclass DEFAULT NULL
)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  filter_col name,
  filter_value text,
  action text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  r record;
  src regclass;
BEGIN
  FOR r IN
    SELECT i.index_id, i.source_nsp, i.source_rel, i.source_oid,
           i.filter_col, i.filter_value, i.filter_is_null
      FROM tci_internal.indexes i
     WHERE (NOT i.valid OR NOT i.published)
       AND (
         source_table IS NULL
         OR i.source_oid = source_table
         OR (i.source_nsp, i.source_rel) = (
              SELECT c.relnamespace::regnamespace::name, c.relname
                FROM pg_class c WHERE c.oid = source_table)
       )
     ORDER BY i.index_id
  LOOP
    BEGIN
      src := format('%I.%I', r.source_nsp, r.source_rel)::regclass;
    EXCEPTION WHEN OTHERS THEN
      index_id := r.index_id;
      source_table_name := format('%I.%I', r.source_nsp, r.source_rel);
      filter_col := r.filter_col;
      filter_value := r.filter_value;
      action := 'skip_missing_relation';
      RETURN NEXT;
      CONTINUE;
    END;

    PERFORM tci_internal.require_admin(src);

    IF r.filter_col IS NULL THEN
      PERFORM tci.rebuild(src);
      action := 'rebuild';
    ELSE
      PERFORM tci.rebuild_filtered(
        src, r.filter_col,
        CASE WHEN r.filter_is_null THEN NULL ELSE r.filter_value END);
      action := 'rebuild_filtered';
    END IF;

    index_id := r.index_id;
    source_table_name := format('%I.%I', r.source_nsp, r.source_rel);
    filter_col := r.filter_col;
    filter_value := r.filter_value;
    RETURN NEXT;
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION tci.list_invalid(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.rebuild_invalid(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.list_invalid(regclass) TO PUBLIC;

-- rebuild_invalid is admin (same as rebuild)
-- grant via grant_admin_execute update below

-- ---------------------------------------------------------------------------
-- maintain_filters: relink before work (post-restore OID drift)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.maintain_filters(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8
) RETURNS TABLE (
  index_id int,
  filter_col name,
  filter_value text,
  sealed bigint,
  compacted bigint,
  n_tail bigint,
  live_runs int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  n_tail_cur bigint;
  n_live int;
  s_rid bigint;
  c_rid bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);

  -- Relink filtered catalog rows (OID/name) before sealing
  FOR idx IN
    SELECT i.* FROM tci_internal.indexes i
    WHERE i.filter_col IS NOT NULL
      AND (
        i.source_oid = source_table
        OR (i.source_nsp, i.source_rel) = (
             SELECT c.relnamespace::regnamespace::name, c.relname
               FROM pg_class c WHERE c.oid = source_table)
      )
    ORDER BY i.index_id
  LOOP
    PERFORM tci_internal.relink_filtered(
      source_table, idx.filter_col,
      CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END);
  END LOOP;

  FOR idx IN
    SELECT i.* FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col IS NOT NULL
      AND i.published AND i.valid
    ORDER BY i.index_id
  LOOP
    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    s_rid := NULL;
    c_rid := NULL;
    IF n_tail_cur >= tail_target THEN
      s_rid := tci.seal_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END,
        GREATEST(tail_target, 8192));
    END IF;
    IF n_live >= max_live_runs THEN
      c_rid := tci.compact_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END);
    END IF;

    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    index_id := idx.index_id;
    filter_col := idx.filter_col;
    filter_value := idx.filter_value;
    sealed := s_rid;
    compacted := c_rid;
    n_tail := n_tail_cur;
    live_runs := n_live;
    RETURN NEXT;
  END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- filter_fit_estimate — cardinality advisor (not a latency guarantee)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.filter_fit_estimate(
  source_table regclass,
  filter_column name
)
RETURNS TABLE (
  filter_col name,
  n_distinct_estimate double precision,
  registered_filters int,
  hint text,
  detail text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  nsp name;
  rel name;
  att name;
  nd double precision;
  nreg int;
  h text;
  d text;
BEGIN
  PERFORM tci_internal.require_select(source_table);

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;

  att := filter_column;

  SELECT s.n_distinct INTO nd
  FROM pg_stats s
  WHERE s.schemaname = nsp
    AND s.tablename = rel
    AND s.attname = att;

  SELECT count(*)::int INTO nreg
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column;

  IF nd IS NULL THEN
    h := 'measure_required';
    d := 'no pg_stats row — ANALYZE then re-check; always microbench';
  ELSIF nd < 0 THEN
    -- negative n_distinct => -fraction of rows that are distinct
    IF abs(nd) <= 0.02 THEN
      h := 'likely_ok';
      d := format('n_distinct=%s (scaled); low relative cardinality', nd);
    ELSIF abs(nd) <= 0.08 THEN
      h := 'measure_required';
      d := format('n_distinct=%s (scaled); mid cardinality — measure vs native', nd);
    ELSE
      h := 'native_may_win';
      d := format('n_distinct=%s (scaled); high relative cardinality', nd);
    END IF;
  ELSE
    IF nd <= 32 THEN
      h := 'likely_ok';
      d := format('n_distinct=%s; typical filtered TCI sweet spot ≤16–32', nd);
    ELSIF nd <= 64 THEN
      h := 'measure_required';
      d := format('n_distinct=%s; measure vs native before registering many filters', nd);
    ELSE
      h := 'native_may_win';
      d := format('n_distinct=%s; at ≥64–256 selective keys native often wins', nd);
    END IF;
  END IF;

  IF nreg > 32 AND h = 'likely_ok' THEN
    h := 'measure_required';
    d := d || format('; already %s registered filters', nreg);
  END IF;

  filter_col := filter_column;
  n_distinct_estimate := nd;
  registered_filters := nreg;
  hint := h;
  detail := d;
  RETURN NEXT;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.filter_fit_estimate(regclass, name) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- Richer health.detail (write-amp / ops hints)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.health(source_table regclass)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  published boolean,
  valid boolean,
  shard_count int,
  generation bigint,
  n_tail bigint,
  live_runs int,
  deltas_sealed bigint,
  deltas_sealed_per_sec double precision,
  deltas_ingested bigint,
  deltas_ingested_per_sec double precision,
  last_seal_at timestamptz,
  seconds_since_reset double precision,
  capacity_ok boolean,
  detail text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);
  INSERT INTO tci_internal.cap_counters(index_id)
  SELECT idx.index_id
   WHERE NOT EXISTS (
     SELECT 1 FROM tci_internal.cap_counters c WHERE c.index_id = idx.index_id
   );

  RETURN QUERY
  SELECT
    i.index_id,
    format('%I.%I', i.source_nsp, i.source_rel)::text,
    i.published,
    i.valid,
    i.shard_count,
    i.generation,
    (SELECT count(*) FROM tci_internal.tail t
      WHERE t.index_id = i.index_id AND t.generation = i.generation),
    (SELECT count(*)::int FROM tci_internal.runs r
      WHERE r.index_id = i.index_id AND r.status = 'live'),
    c.deltas_sealed,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_sealed / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.deltas_ingested,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_ingested / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.last_seal_at,
    EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at))::float8,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN false
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
           AND EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 60
           AND (c.deltas_sealed / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1))
               < (c.deltas_ingested / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1)) * 0.5
        THEN false
      ELSE true
    END,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN
        'invalid_or_unpublished — count uses native fallback; run tci.rebuild / rebuild_invalid'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
           AND EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 60
           AND (c.deltas_sealed / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1))
               < (c.deltas_ingested / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1)) * 0.5
        THEN 'capacity_lag — seal slower than ingest; raise maint frequency/budget or reduce writers'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
        THEN 'tail_large — run tci.maintain / maintain_filters; expect count latency growth'::text
      WHEN (SELECT count(*)::int FROM tci_internal.runs r
             WHERE r.index_id = i.index_id AND r.status = 'live') > 16
        THEN 'live_runs_high — compact; each live run adds decode cost'::text
      WHEN i.filter_col IS NOT NULL THEN
        format('filtered ok (col=%s); vacuum tci_internal.tail/chunks under write load', i.filter_col)::text
      ELSE 'ok — monitor n_tail vs seal rate; vacuum tci_internal under sustained writes'::text
    END
  FROM tci_internal.indexes i
  JOIN tci_internal.cap_counters c ON c.index_id = i.index_id
  WHERE i.index_id = idx.index_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- admin_procedures: include rebuild_invalid
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.admin_procedures()
RETURNS SETOF regprocedure
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.oid::regprocedure
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'tci'
    AND p.proname = ANY (ARRAY[
      'seal', 'seal_bounded', 'compact', 'compact_pairwise', 'compact_budget',
      'maintain', 'invalidate', 'rebuild', 'capacity_reset', 'set_shard_count',
      'maint_history',
      'rebuild_filtered', 'drop_filtered', 'invalidate_filtered',
      'seal_filtered', 'compact_filtered', 'maintain_filters',
      'rebuild_invalid'
    ]);
$$;

REVOKE ALL ON FUNCTION tci.rebuild_invalid(regclass) FROM PUBLIC;

-- Re-grant to current table owners
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT roles.rolname AS rolname
    FROM tci_internal.indexes i
    JOIN pg_class c ON c.oid = i.source_oid
    JOIN pg_roles roles ON roles.oid = c.relowner
  LOOP
    PERFORM tci_internal.grant_admin_execute(r.rolname);
  END LOOP;
END $$;

COMMENT ON FUNCTION tci.list_invalid(regclass) IS
  'List unpublished or invalid TCI indexes (optional source filter).';
COMMENT ON FUNCTION tci.rebuild_invalid(regclass) IS
  'Rebuild all invalid/unpublished indexes (unfiltered + filtered); admin.';
COMMENT ON FUNCTION tci.filter_fit_estimate(regclass, name) IS
  'Cardinality hint for filtered TCI vs native (not a latency guarantee).';
COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.10 — pilot-ops hardening)';
