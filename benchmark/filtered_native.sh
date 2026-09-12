#!/usr/bin/env bash
# Native filtered TCI vs native COUNT vs slice-table spike.
# Disposable DB. Env: ROWS SEGMENTS SKEW MODE LOOPS WARM PG*
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
PGHOST=${PGHOST:-/tmp}
PGPORT=${PGPORT:-55432}
PGUSER=${PGUSER:-$(whoami)}
PGDATABASE=${PGDATABASE:-tci_filt_bench}
ROWS=${ROWS:-100000}
SEGMENTS=${SEGMENTS:-4}
SKEW=${SKEW:-uniform}
MODE=${MODE:-filtered_tci}   # native | filtered_tci | slice_tci
LOOPS=${LOOPS:-200}
WARM=${WARM:-50}
SEG=${SEG:-0}
export PGHOST PGPORT PGUSER PGDATABASE

PSQL=(psql -v ON_ERROR_STOP=1 -X -q)

echo "== filtered native bench =="
echo "DB=$PGDATABASE ROWS=$ROWS SEGMENTS=$SEGMENTS SKEW=$SKEW MODE=$MODE SEG=$SEG"

psql -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$PGDATABASE' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
psql -d postgres -c "DROP DATABASE IF EXISTS $PGDATABASE;"
psql -d postgres -c "CREATE DATABASE $PGDATABASE;"

"${PSQL[@]}" <<SQL
CREATE EXTENSION pg_tci;
\\i $ROOT/filtered_native_lib.sql
SELECT filt_bench.install($SEGMENTS, $ROWS, '$SKEW', '$MODE');
SELECT filt_bench.assert_match();
SELECT * FROM filt_bench.storage_bytes();

CREATE TEMP TABLE _lat (kind text, ms double precision);

DO \$\$
DECLARE
  ts timestamptz := timestamptz '2024-01-01 12:00:00+00';
  seg int := $SEG;
  i int;
  t0 timestamptz;
  dummy bigint;
  warm int := $WARM;
  loops int := $LOOPS;
BEGIN
  FOR i IN 1..warm LOOP
    dummy := filt_bench.count(seg, ts);
    dummy := filt_bench.native_count(seg, ts);
  END LOOP;

  FOR i IN 1..loops LOOP
    t0 := clock_timestamp();
    dummy := filt_bench.count(seg, ts);
    INSERT INTO _lat VALUES ('mode', EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);

    t0 := clock_timestamp();
    dummy := filt_bench.native_count(seg, ts);
    INSERT INTO _lat VALUES ('native', EXTRACT(EPOCH FROM (clock_timestamp() - t0)) * 1000.0);
  END LOOP;
END \$\$;

SELECT kind,
       round(percentile_cont(0.50) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p50_ms,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p95_ms,
       round(percentile_cont(0.99) WITHIN GROUP (ORDER BY ms)::numeric, 3) AS p99_ms
FROM _lat
GROUP BY kind
ORDER BY kind;

-- Write-path micro: insert/update/move/delete + exactness
DO \$\$
DECLARE
  rid bigint;
  n int;
BEGIN
  SELECT m.n_segments INTO n FROM filt_bench.meta m WHERE m.id = 1;
  INSERT INTO sessions(segment, started_at, ended_at)
  VALUES (0, timestamptz '2024-01-01 11:59+00', timestamptz '2024-01-01 12:01+00')
  RETURNING sessions.id INTO rid;
  PERFORM filt_bench.assert_match();
  UPDATE sessions SET ended_at = timestamptz '2024-01-01 12:30+00' WHERE sessions.id = rid;
  PERFORM filt_bench.assert_match();
  IF n > 1 THEN
    UPDATE sessions SET segment = 1 WHERE sessions.id = rid;
    PERFORM filt_bench.assert_match();
    UPDATE sessions SET segment = 0 WHERE sessions.id = rid;
    PERFORM filt_bench.assert_match();
  END IF;
  DELETE FROM sessions WHERE sessions.id = rid;
  PERFORM filt_bench.assert_match();
END \$\$;

SELECT 'write_path_ok' AS status;
SQL
