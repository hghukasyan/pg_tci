-- Native filtered TCI benchmark helpers (disposable DBs only).
-- Modes: native | filtered_tci | slice_tci
--
--   SELECT filt_bench.install(n_segments, n_rows, skew, mode);
--   SELECT filt_bench.assert_match(ts, seg);
--   SELECT filt_bench.count(seg, ts);

CREATE SCHEMA IF NOT EXISTS filt_bench;

CREATE TABLE IF NOT EXISTS filt_bench.meta (
  id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  n_segments int NOT NULL,
  skew text NOT NULL,
  mode text NOT NULL,
  n_rows int NOT NULL
);

CREATE OR REPLACE FUNCTION filt_bench.teardown()
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  DROP TABLE IF EXISTS sessions CASCADE;
  FOR r IN
    SELECT c.relname FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND c.relname ~ '^sessions_seg_[0-9]+$'
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS %I CASCADE', r.relname);
  END LOOP;
  -- Keep filt_bench.sync_sessions() — recreated by this file / needed by install.
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.pick_segment(u float8, n int, skew text)
RETURNS int LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN skew = 'hot90' THEN
      CASE WHEN u < 0.90 THEN 0
           ELSE 1 + ((u - 0.90) * 1e9)::bigint % GREATEST(n - 1, 1)
      END
    ELSE (u * 1e9)::bigint % n
  END::int;
$$;

CREATE OR REPLACE FUNCTION filt_bench.sync_sessions()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    EXECUTE format(
      'INSERT INTO %I (id, started_at, ended_at) VALUES ($1,$2,$3)',
      'sessions_seg_' || NEW.segment
    ) USING NEW.id, NEW.started_at, NEW.ended_at;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('DELETE FROM %I WHERE id = $1', 'sessions_seg_' || OLD.segment)
      USING OLD.id;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.segment IS DISTINCT FROM NEW.segment THEN
      EXECUTE format('DELETE FROM %I WHERE id = $1', 'sessions_seg_' || OLD.segment)
        USING OLD.id;
      EXECUTE format(
        'INSERT INTO %I (id, started_at, ended_at) VALUES ($1,$2,$3)',
        'sessions_seg_' || NEW.segment
      ) USING NEW.id, NEW.started_at, NEW.ended_at;
    ELSIF OLD.started_at IS DISTINCT FROM NEW.started_at
       OR OLD.ended_at IS DISTINCT FROM NEW.ended_at THEN
      EXECUTE format(
        'UPDATE %I SET started_at=$2, ended_at=$3 WHERE id=$1',
        'sessions_seg_' || NEW.segment
      ) USING NEW.id, NEW.started_at, NEW.ended_at;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.install(
  n_segments int DEFAULT 4,
  n_rows int DEFAULT 100000,
  skew text DEFAULT 'uniform',
  mode text DEFAULT 'filtered_tci'  -- native | filtered_tci | slice_tci
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  i int;
  t0 timestamptz := clock_timestamp();
BEGIN
  IF n_segments < 1 OR n_segments > 256 THEN
    RAISE EXCEPTION 'n_segments out of range';
  END IF;
  IF skew NOT IN ('uniform', 'hot90') THEN
    RAISE EXCEPTION 'skew must be uniform|hot90';
  END IF;
  IF mode NOT IN ('native', 'filtered_tci', 'slice_tci') THEN
    RAISE EXCEPTION 'mode must be native|filtered_tci|slice_tci';
  END IF;

  PERFORM filt_bench.teardown();
  INSERT INTO filt_bench.meta(id, n_segments, skew, mode, n_rows)
  VALUES (1, n_segments, skew, mode, n_rows)
  ON CONFLICT (id) DO UPDATE
    SET n_segments = EXCLUDED.n_segments,
        skew = EXCLUDED.skew,
        mode = EXCLUDED.mode,
        n_rows = EXCLUDED.n_rows;

  EXECUTE format($c$
    CREATE TABLE sessions (
      id bigserial PRIMARY KEY,
      segment int NOT NULL CHECK (segment >= 0 AND segment < %s),
      started_at timestamptz NOT NULL,
      ended_at timestamptz
    )
  $c$, n_segments);

  -- Fair native baselines
  CREATE INDEX sessions_seg_started_idx ON sessions (segment, started_at);
  CREATE INDEX sessions_seg_ended_idx ON sessions (segment, ended_at);
  -- Partial index on hot segment (for mode comparisons that include D)
  CREATE INDEX sessions_seg0_partial_started
    ON sessions (started_at) WHERE segment = 0;
  CREATE INDEX sessions_seg0_partial_ended
    ON sessions (ended_at) WHERE segment = 0;

  INSERT INTO sessions(segment, started_at, ended_at)
  SELECT filt_bench.pick_segment(random(), n_segments, skew),
         timestamptz '2024-01-01 00:00:00+00' + ((g % 1440) || ' minutes')::interval,
         CASE WHEN random() < 0.15 THEN NULL
              ELSE timestamptz '2024-01-01 00:00:00+00'
                   + (((g % 1440) + 30 + (random()*120)::int) || ' minutes')::interval
         END
  FROM generate_series(1, n_rows) g;

  ANALYZE sessions;

  IF mode = 'filtered_tci' THEN
    FOR i IN 0..(n_segments - 1) LOOP
      PERFORM tci.create_filtered(
        'sessions'::regclass, 'started_at', 'ended_at',
        'segment', i::text);
    END LOOP;
  ELSIF mode = 'slice_tci' THEN
    FOR i IN 0..(n_segments - 1) LOOP
      EXECUTE format($f$
        CREATE TABLE sessions_seg_%s (
          id bigint PRIMARY KEY,
          started_at timestamptz NOT NULL,
          ended_at timestamptz
        )
      $f$, i);
      EXECUTE format($f$
        INSERT INTO sessions_seg_%s(id, started_at, ended_at)
        SELECT id, started_at, ended_at FROM sessions WHERE segment = %s
      $f$, i, i);
      EXECUTE format(
        'CREATE INDEX ON sessions_seg_%s (started_at)', i);
      EXECUTE format(
        'CREATE INDEX ON sessions_seg_%s (ended_at)', i);
      PERFORM tci.create(
        format('sessions_seg_%s', i)::regclass, 'started_at', 'ended_at');
    END LOOP;
    CREATE TRIGGER filt_bench_sync
      AFTER INSERT OR UPDATE OR DELETE ON sessions
      FOR EACH ROW EXECUTE FUNCTION filt_bench.sync_sessions();
  END IF;

  RAISE NOTICE 'filt_bench.install done mode=% rows=% segs=% in % ms',
    mode, n_rows, n_segments,
    (EXTRACT(EPOCH FROM clock_timestamp() - t0) * 1000)::int;
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.count(seg int, ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql STABLE AS $$
DECLARE
  mode text;
  v bigint;
BEGIN
  SELECT m.mode INTO mode FROM filt_bench.meta m WHERE m.id = 1;
  IF mode = 'filtered_tci' THEN
    RETURN tci.count_at_filtered('sessions'::regclass, ts, 'segment', seg::text);
  ELSIF mode = 'slice_tci' THEN
    RETURN tci.count_at(format('sessions_seg_%s', seg)::regclass, ts);
  ELSE
    SELECT count(*) INTO v FROM sessions s
     WHERE s.segment = seg
       AND s.started_at <= ts
       AND (s.ended_at IS NULL OR s.ended_at > ts);
    RETURN v;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.native_count(seg int, ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql STABLE AS $$
DECLARE v bigint;
BEGIN
  SELECT count(*)::bigint INTO v FROM sessions s
   WHERE s.segment = seg
     AND s.started_at <= ts
     AND (s.ended_at IS NULL OR s.ended_at > ts);
  RETURN v;
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.assert_match(ts timestamptz DEFAULT timestamptz '2024-01-01 12:00:00+00')
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
  n int;
  seg int;
  a bigint;
  b bigint;
BEGIN
  SELECT n_segments INTO n FROM filt_bench.meta WHERE id = 1;
  FOR seg IN 0..(n - 1) LOOP
    a := filt_bench.count(seg, ts);
    b := filt_bench.native_count(seg, ts);
    IF a IS DISTINCT FROM b THEN
      RAISE EXCEPTION 'mismatch seg=% ts=% mode_count=% native=%', seg, ts, a, b;
    END IF;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION filt_bench.storage_bytes()
RETURNS TABLE(kind text, bytes bigint)
LANGUAGE plpgsql STABLE AS $$
DECLARE
  mode text;
  n int;
  i int;
  b bigint;
BEGIN
  SELECT m.mode, m.n_segments INTO mode, n FROM filt_bench.meta m WHERE id = 1;

  SELECT pg_total_relation_size('sessions'::regclass) INTO b;
  kind := 'sessions_heap_idx'; bytes := b; RETURN NEXT;

  IF mode = 'filtered_tci' THEN
    SELECT coalesce(sum(pg_column_size(c.payload)),0)
         + coalesce((SELECT sum(pg_column_size(t.*)) FROM tci_internal.tail t
                     JOIN tci_internal.indexes i ON i.index_id = t.index_id
                     WHERE i.source_oid = 'sessions'::regclass), 0)
      INTO b
    FROM tci_internal.chunks c
    JOIN tci_internal.indexes i ON i.index_id = c.index_id
    WHERE i.source_oid = 'sessions'::regclass AND i.filter_col IS NOT NULL;
    kind := 'tci_filtered_payload_est'; bytes := b; RETURN NEXT;

    SELECT coalesce(sum(pg_total_relation_size(c.oid)),0) INTO b
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'tci_internal';
    kind := 'tci_internal_relations'; bytes := b; RETURN NEXT;

  ELSIF mode = 'slice_tci' THEN
    b := 0;
    FOR i IN 0..(n-1) LOOP
      b := b + pg_total_relation_size(format('sessions_seg_%s', i)::regclass);
    END LOOP;
    kind := 'slice_tables_total'; bytes := b; RETURN NEXT;

    SELECT coalesce(sum(pg_total_relation_size(c.oid)),0) INTO b
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'tci_internal';
    kind := 'tci_internal_relations'; bytes := b; RETURN NEXT;
  END IF;
END;
$$;
