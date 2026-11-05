#!/usr/bin/env bash
# Segment-TCI spike smoke: sync triggers + correctness + read latency.
# Experiment only — not a product API. Disposable DB.
#
# Env: ROWS SEGMENTS SKEW=uniform|hot90 LOOPS WARM  PGHOST PGPORT PGUSER PGDATABASE
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
PGHOST=${PGHOST:-/tmp}
PGPORT=${PGPORT:-55432}
PGUSER=${PGUSER:-$(whoami)}
PGDATABASE=${PGDATABASE:-postgres}
ROWS=${ROWS:-100000}
SEGMENTS=${SEGMENTS:-4}
SKEW=${SKEW:-uniform}
LOOPS=${LOOPS:-200}
WARM=${WARM:-50}
export PGHOST PGPORT PGUSER PGDATABASE

PSQL=(psql -v ON_ERROR_STOP=1 -X -q)

echo "== segment spike env =="
echo "ROWS=$ROWS SEGMENTS=$SEGMENTS SKEW=$SKEW LOOPS=$LOOPS WARM=$WARM"
psql -c "SELECT version();"
psql -c "SELECT extversion FROM pg_extension WHERE extname='pg_tci';" || {
  echo "CREATE EXTENSION first (make install && CREATE EXTENSION pg_tci)" >&2
  exit 1
}

"${PSQL[@]}" <<SQL
CREATE EXTENSION IF NOT EXISTS pg_tci;
CREATE SCHEMA IF NOT EXISTS tci_spike;
\\i $ROOT/segment_spike_lib.sql

SELECT tci_spike.install($SEGMENTS, $ROWS, '$SKEW');
SELECT tci_spike.assert_match();

-- Write-path via trigger (insert / update times / move segment / delete)
INSERT INTO sessions(segment, started_at, ended_at)
VALUES (
  0,
  timestamptz '2024-01-01 11:59:00+00',
  timestamptz '2024-01-01 12:01:00+00'
) RETURNING id \\gset

UPDATE sessions
   SET ended_at = timestamptz '2024-01-01 12:30:00+00'
 WHERE id = :id;

SELECT tci_spike.assert_match();

-- Move across segments when possible (no-op UPDATE if SEGMENTS=1)
UPDATE sessions SET segment = CASE
  WHEN (SELECT n_segments FROM tci_spike.meta WHERE id = 1) > 1 THEN 1 ELSE 0
END WHERE id = :id;
UPDATE sessions SET segment = 0 WHERE id = :id;
SELECT tci_spike.assert_match();

DELETE FROM sessions WHERE id = :id;
SELECT tci_spike.assert_match();

SELECT segment, count(*) AS n_rows
FROM sessions
GROUP BY segment
ORDER BY segment;

SELECT 'sessions_seg_0' AS slice, n_tail, live_runs, published, valid
FROM tci.stats('sessions_seg_0'::regclass);

CREATE TEMP TABLE _lat (kind text, ms double precision);

DO \$\$
DECLARE
  ts timestamptz := timestamptz '2024-01-01 12:00:00+00';
  seg int := 0;
  i int;
  t0 timestamptz;
  t1 timestamptz;
  dummy bigint;
  warm int := $WARM;
  loops int := $LOOPS;
BEGIN
  FOR i IN 1..warm LOOP
    PERFORM tci_spike.count_at_segment(seg, ts);
    PERFORM count(*) FROM sessions s
     WHERE s.segment = seg
       AND s.started_at <= ts
       AND (s.ended_at IS NULL OR s.ended_at > ts);
  END LOOP;

  FOR i IN 1..loops LOOP
    t0 := clock_timestamp();
    dummy := tci_spike.count_at_segment(seg, ts);
    t1 := clock_timestamp();
    INSERT INTO _lat VALUES ('tci_segment', 1000.0 * extract(epoch FROM (t1 - t0)));
  END LOOP;

  FOR i IN 1..loops LOOP
    t0 := clock_timestamp();
    SELECT count(*) INTO dummy FROM sessions s
     WHERE s.segment = seg
       AND s.started_at <= ts
       AND (s.ended_at IS NULL OR s.ended_at > ts);
    t1 := clock_timestamp();
    INSERT INTO _lat VALUES ('native_filtered', 1000.0 * extract(epoch FROM (t1 - t0)));
  END LOOP;
END \$\$;

SELECT kind,
       round(percentile_cont(0.50) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p50_ms,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p95_ms,
       round(percentile_cont(0.99) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p99_ms
FROM _lat
GROUP BY kind
ORDER BY kind;
SQL

echo "== segment spike OK =="
