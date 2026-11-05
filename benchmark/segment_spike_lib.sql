-- Shared segment-spike helpers (experiment only, not product API).
-- Call after: CREATE EXTENSION pg_tci; CREATE SCHEMA tci_spike;
--
--   SELECT tci_spike.install(n_segments := 4, n_rows := 100000, skew := 'uniform');
--   SELECT tci_spike.assert_match(ts);
--   -- writers only touch `sessions`; trigger mirrors into sessions_seg_* (+ TCI)

CREATE TABLE IF NOT EXISTS tci_spike.meta (
  id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  n_segments int NOT NULL,
  skew text NOT NULL
);

CREATE OR REPLACE FUNCTION tci_spike.teardown()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  r record;
BEGIN
  DROP TABLE IF EXISTS sessions CASCADE;
  FOR r IN
    SELECT c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname ~ '^sessions_seg_[0-9]+$'
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS %I CASCADE', r.relname);
  END LOOP;
  -- Keep tci_spike.sync_sessions() — recreated by this file; trigger needs it.
  DROP FUNCTION IF EXISTS tci_spike.seg_table(int);
  DROP FUNCTION IF EXISTS tci_spike.count_at_segment(int, timestamptz);
  DROP FUNCTION IF EXISTS tci_spike.assert_match(timestamptz);
  DROP FUNCTION IF EXISTS tci_spike.pick_segment(float8);
END;
$$;

CREATE OR REPLACE FUNCTION tci_spike.sync_sessions()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    EXECUTE format(
      'INSERT INTO %I (id, started_at, ended_at) VALUES ($1,$2,$3)',
      'sessions_seg_' || NEW.segment
    ) USING NEW.id, NEW.started_at, NEW.ended_at;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format(
      'DELETE FROM %I WHERE id = $1',
      'sessions_seg_' || OLD.segment
    ) USING OLD.id;
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.segment IS DISTINCT FROM NEW.segment THEN
      EXECUTE format(
        'DELETE FROM %I WHERE id = $1',
        'sessions_seg_' || OLD.segment
      ) USING OLD.id;
      EXECUTE format(
        'INSERT INTO %I (id, started_at, ended_at) VALUES ($1,$2,$3)',
        'sessions_seg_' || NEW.segment
      ) USING NEW.id, NEW.started_at, NEW.ended_at;
    ELSIF OLD.started_at IS DISTINCT FROM NEW.started_at
       OR OLD.ended_at   IS DISTINCT FROM NEW.ended_at THEN
      EXECUTE format(
        'UPDATE %I SET started_at = $2, ended_at = $3 WHERE id = $1',
        'sessions_seg_' || NEW.segment
      ) USING NEW.id, NEW.started_at, NEW.ended_at;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION tci_spike.install(
  n_segments int DEFAULT 4,
  n_rows int DEFAULT 100000,
  skew text DEFAULT 'uniform'  -- uniform | hot90
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  i int;
  seg int;
BEGIN
  IF n_segments < 1 OR n_segments > 256 THEN
    RAISE EXCEPTION 'n_segments out of range: %', n_segments;
  END IF;
  IF skew NOT IN ('uniform', 'hot90') THEN
    RAISE EXCEPTION 'skew must be uniform|hot90, got %', skew;
  END IF;

  PERFORM tci_spike.teardown();
  INSERT INTO tci_spike.meta (id, n_segments, skew)
  VALUES (1, n_segments, skew)
  ON CONFLICT (id) DO UPDATE
    SET n_segments = EXCLUDED.n_segments,
        skew = EXCLUDED.skew;

  EXECUTE format($c$
    CREATE TABLE sessions (
      id         bigserial PRIMARY KEY,
      segment    int NOT NULL CHECK (segment >= 0 AND segment < %s),
      started_at timestamptz NOT NULL,
      ended_at   timestamptz
    )
  $c$, n_segments);
  CREATE INDEX sessions_seg_started_idx ON sessions (segment, started_at);
  CREATE INDEX sessions_seg_ended_idx   ON sessions (segment, ended_at);

  FOR i IN 0..(n_segments - 1) LOOP
    EXECUTE format($f$
      CREATE TABLE sessions_seg_%s (
        id bigint PRIMARY KEY,
        started_at timestamptz NOT NULL,
        ended_at   timestamptz
      );
      CREATE INDEX ON sessions_seg_%s (started_at);
      CREATE INDEX ON sessions_seg_%s (ended_at);
      CREATE INDEX ON sessions_seg_%s (started_at, ended_at);
    $f$, i, i, i, i);
  END LOOP;

  -- Bulk load without trigger, then attach sync
  IF skew = 'uniform' THEN
    INSERT INTO sessions (segment, started_at, ended_at)
    SELECT
      (g % n_segments),
      timestamptz '2024-01-01 00:00:00+00' + (g || ' seconds')::interval,
      CASE WHEN g % 7 = 0 THEN NULL
           ELSE timestamptz '2024-01-01 00:00:00+00'
                + ((g + 300 + (g % 100)) || ' seconds')::interval
      END
    FROM generate_series(1, n_rows) g;
  ELSE
    -- hot90: segment 0 ≈ 90%, others share 10%
    INSERT INTO sessions (segment, started_at, ended_at)
    SELECT
      CASE
        WHEN (g % 10) <> 0 THEN 0
        ELSE 1 + (g % greatest(n_segments - 1, 1))
      END,
      timestamptz '2024-01-01 00:00:00+00' + (g || ' seconds')::interval,
      CASE WHEN g % 7 = 0 THEN NULL
           ELSE timestamptz '2024-01-01 00:00:00+00'
                + ((g + 300 + (g % 100)) || ' seconds')::interval
      END
    FROM generate_series(1, n_rows) g;
  END IF;

  FOR i IN 0..(n_segments - 1) LOOP
    EXECUTE format($f$
      INSERT INTO sessions_seg_%s (id, started_at, ended_at)
      SELECT id, started_at, ended_at FROM sessions WHERE segment = %s
    $f$, i, i);
    EXECUTE format(
      'SELECT tci.create(%L::regclass, %L, %L)',
      'sessions_seg_' || i, 'started_at', 'ended_at'
    );
    EXECUTE format('SELECT tci.seal(%L::regclass)', 'sessions_seg_' || i);
    EXECUTE format('ANALYZE %I', 'sessions_seg_' || i);
  END LOOP;

  ANALYZE sessions;

  CREATE TRIGGER sessions_sync_aiud
    AFTER INSERT OR UPDATE OR DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION tci_spike.sync_sessions();

  CREATE OR REPLACE FUNCTION tci_spike.seg_table(seg int)
  RETURNS regclass
  LANGUAGE plpgsql
  STABLE
  STRICT
  AS $f$
  DECLARE
    n int;
  BEGIN
    SELECT n_segments INTO STRICT n FROM tci_spike.meta WHERE id = 1;
    IF seg < 0 OR seg >= n THEN
      RAISE EXCEPTION 'segment out of range: %', seg;
    END IF;
    RETURN ('sessions_seg_' || seg)::regclass;
  END;
  $f$;

  CREATE OR REPLACE FUNCTION tci_spike.count_at_segment(seg int, ts timestamptz)
  RETURNS bigint
  LANGUAGE sql
  STABLE
  STRICT
  AS $f$
    SELECT tci.count_at(tci_spike.seg_table(seg), ts);
  $f$;

  CREATE OR REPLACE FUNCTION tci_spike.pick_segment(u float8)
  RETURNS int
  LANGUAGE plpgsql
  STABLE
  STRICT
  AS $f$
  DECLARE
    n int;
    sk text;
  BEGIN
    SELECT n_segments, skew INTO STRICT n, sk FROM tci_spike.meta WHERE id = 1;
    IF sk = 'hot90' AND n > 1 THEN
      IF u < 0.90 THEN
        RETURN 0;
      END IF;
      RETURN 1 + floor((u - 0.90) / 0.10 * (n - 1))::int;
    END IF;
    RETURN floor(u * n)::int % n;
  END;
  $f$;

  CREATE OR REPLACE FUNCTION tci_spike.assert_match(ts timestamptz DEFAULT timestamptz '2024-01-01 12:00:00+00')
  RETURNS void
  LANGUAGE plpgsql
  AS $f$
  DECLARE
    seg int;
    c_tci bigint;
    c_nat bigint;
    n int;
  BEGIN
    SELECT n_segments INTO STRICT n FROM tci_spike.meta WHERE id = 1;
    FOR seg IN 0..(n - 1) LOOP
      c_tci := tci_spike.count_at_segment(seg, ts);
      SELECT count(*) INTO c_nat
        FROM sessions s
       WHERE s.segment = seg
         AND s.started_at <= ts
         AND (s.ended_at IS NULL OR s.ended_at > ts);
      IF c_tci IS DISTINCT FROM c_nat THEN
        RAISE EXCEPTION 'mismatch seg=% tci=% native=%', seg, c_tci, c_nat;
      END IF;
    END LOOP;
  END;
  $f$;
END;
$$;
