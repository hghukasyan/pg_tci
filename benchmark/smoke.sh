#!/usr/bin/env bash
# Fast correctness + latency smoke for pg_tci (disposable DB).
set -euo pipefail

PGHOST=${PGHOST:-/tmp}
PGPORT=${PGPORT:-55432}
PGUSER=${PGUSER:-$(whoami)}
PGDATABASE=${PGDATABASE:-postgres}
export PGHOST PGPORT PGUSER PGDATABASE

PSQL=(psql -v ON_ERROR_STOP=1 -X -q)

echo "== env =="
psql -c "SELECT version();"
psql -c "SELECT extversion FROM pg_extension WHERE extname='pg_tci';" || {
  echo "CREATE EXTENSION first (make install && CREATE EXTENSION pg_tci)" >&2
  exit 1
}

"${PSQL[@]}" <<'SQL'
DROP TABLE IF EXISTS tci_smoke CASCADE;
CREATE TABLE tci_smoke (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

-- Deterministic 10k intervals
INSERT INTO tci_smoke (started_at, ended_at)
SELECT
  timestamptz '2024-01-01 00:00:00+00' + (g || ' minutes')::interval,
  CASE WHEN g % 7 = 0 THEN NULL
       ELSE timestamptz '2024-01-01 00:00:00+00' + ((g + 15) || ' minutes')::interval
  END
FROM generate_series(0, 9999) g;

CREATE INDEX ON tci_smoke (started_at);
CREATE INDEX ON tci_smoke (ended_at);
CREATE INDEX ON tci_smoke (started_at, ended_at);

SELECT tci.create('tci_smoke'::regclass, 'started_at', 'ended_at');

-- Same-snapshot exactness
DO $$
DECLARE
  ts timestamptz := timestamptz '2024-01-01 01:00:00+00';
  c_tci bigint;
  c_nat bigint;
BEGIN
  PERFORM tci.seal('tci_smoke'::regclass);
  SELECT tci.count_at('tci_smoke', ts) INTO c_tci;
  SELECT count(*) INTO c_nat FROM tci_smoke s
   WHERE s.started_at <= ts AND (s.ended_at IS NULL OR s.ended_at > ts);
  IF c_tci IS DISTINCT FROM c_nat THEN
    RAISE EXCEPTION 'mismatch sealed: tci=% native=%', c_tci, c_nat;
  END IF;

  INSERT INTO tci_smoke(started_at, ended_at)
  VALUES (ts - interval '1 minute', ts + interval '1 minute');

  SELECT tci.count_at('tci_smoke', ts) INTO c_tci;
  SELECT count(*) INTO c_nat FROM tci_smoke s
   WHERE s.started_at <= ts AND (s.ended_at IS NULL OR s.ended_at > ts);
  IF c_tci IS DISTINCT FROM c_nat THEN
    RAISE EXCEPTION 'mismatch with tail: tci=% native=%', c_tci, c_nat;
  END IF;
END $$;

SELECT tci.seal_bounded('tci_smoke'::regclass, 4096) AS sealed_rows;
SELECT tci.compact_pairwise('tci_smoke'::regclass) AS compacted;
SELECT * FROM tci.stats('tci_smoke'::regclass);

-- Warm latency (statement clocks; illustrative only)
CREATE TEMP TABLE _lat (kind text, ms double precision);
DO $$
DECLARE
  ts timestamptz := timestamptz '2024-01-01 02:00:00+00';
  i int;
  t0 timestamptz;
  t1 timestamptz;
  dummy bigint;
BEGIN
  FOR i IN 1..50 LOOP
    PERFORM tci.count_at('tci_smoke', ts);  -- warmup
  END LOOP;
  FOR i IN 1..200 LOOP
    t0 := clock_timestamp();
    dummy := tci.count_at('tci_smoke', ts);
    t1 := clock_timestamp();
    INSERT INTO _lat VALUES ('tci', 1000.0 * extract(epoch FROM (t1 - t0)));
  END LOOP;
  FOR i IN 1..50 LOOP
    PERFORM count(*) FROM tci_smoke s
     WHERE s.started_at <= ts AND (s.ended_at IS NULL OR s.ended_at > ts);
  END LOOP;
  FOR i IN 1..200 LOOP
    t0 := clock_timestamp();
    SELECT count(*) INTO dummy FROM tci_smoke s
     WHERE s.started_at <= ts AND (s.ended_at IS NULL OR s.ended_at > ts);
    t1 := clock_timestamp();
    INSERT INTO _lat VALUES ('native', 1000.0 * extract(epoch FROM (t1 - t0)));
  END LOOP;
END $$;

SELECT kind,
       round(percentile_cont(0.50) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p50_ms,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p95_ms,
       round(percentile_cont(0.99) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p99_ms
FROM _lat
GROUP BY kind
ORDER BY kind;

SELECT version() AS pg_version;
SQL

echo "== smoke OK =="
