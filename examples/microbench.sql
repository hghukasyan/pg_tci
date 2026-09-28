-- Microbench: same-snapshot correctness + EXPLAIN ANALYZE latency.
-- Edit the sessions table name / filter / probe below to match your schema.
-- Do NOT reuse research-cluster numbers from docs as your results.

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pg_tci;

-- Optional: create indexes if missing (comment out when already created)
-- SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at');
-- SELECT tci.create_filtered(
--   'sessions'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise');

-- ---- Correctness: one snapshot ----
BEGIN ISOLATION LEVEL REPEATABLE READ;

SELECT
  tci.count_at('sessions'::regclass, timestamptz '2024-01-01 12:00:00+00') AS tci_unf,
  (SELECT count(*) FROM sessions s
    WHERE s.started_at <= timestamptz '2024-01-01 12:00:00+00'
      AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-01-01 12:00:00+00')) AS native_unf;

SELECT
  tci.count_at_filtered(
    'sessions'::regclass, timestamptz '2024-01-01 12:00:00+00',
    'segment', 'enterprise') AS tci_filt,
  (SELECT count(*) FROM sessions s
    WHERE s.segment = 'enterprise'
      AND s.started_at <= timestamptz '2024-01-01 12:00:00+00'
      AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-01-01 12:00:00+00')) AS native_filt;

COMMIT;

-- ---- Latency (warm): run each block 3×; record your own timings ----
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT tci.count_at('sessions'::regclass, timestamptz '2024-01-01 12:00:00+00');

EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT count(*) FROM sessions s
 WHERE s.started_at <= timestamptz '2024-01-01 12:00:00+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-01-01 12:00:00+00');

EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT tci.count_at_filtered(
  'sessions'::regclass, timestamptz '2024-01-01 12:00:00+00',
  'segment', 'enterprise');

EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT count(*) FROM sessions s
 WHERE s.segment = 'enterprise'
   AND s.started_at <= timestamptz '2024-01-01 12:00:00+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-01-01 12:00:00+00');

SELECT * FROM tci.health('sessions'::regclass);
SELECT * FROM tci.list_filters('sessions'::regclass);
SELECT * FROM tci.storage_bytes('sessions'::regclass);
