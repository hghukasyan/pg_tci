-- Filtered TCI hardening audit (disposable DB). Emits NOTICE PASS/FAIL lines.
\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS pg_tci;

DROP TABLE IF EXISTS audit_sessions CASCADE;
CREATE TABLE audit_sessions (
  id bigserial PRIMARY KEY,
  segment text,
  region int NOT NULL DEFAULT 0,
  note text,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO audit_sessions(segment, region, note, started_at, ended_at) VALUES
  ('enterprise', 1, 'a', '2024-01-01 10:00+00', '2024-01-01 11:00+00'),
  ('enterprise', 1, 'b', '2024-01-01 10:30+00', NULL),
  ('smb', 2, 'c', '2024-01-01 10:00+00', '2024-01-01 12:00+00'),
  (NULL, 3, 'n', '2024-01-01 10:00+00', '2024-01-01 11:00+00'),
  ('weird''quote', 4, 'q', '2024-01-01 10:00+00', '2024-01-01 11:00+00');

-- Unfiltered + filtered coexistence
SELECT tci.create('audit_sessions'::regclass, 'started_at', 'ended_at');
SELECT tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise');
SELECT tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'segment', 'smb');
SELECT tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'segment', NULL);
SELECT tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'segment', 'weird''quote');
SELECT tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'region', '1');

CREATE OR REPLACE FUNCTION audit_eq(label text, a bigint, b bigint) RETURNS void AS $$
BEGIN
  IF a IS DISTINCT FROM b THEN
    RAISE EXCEPTION 'FAIL %: tci=% native=%', label, a, b;
  END IF;
  RAISE NOTICE 'PASS % (%=%)', label, a, b;
END $$ LANGUAGE plpgsql;

DO $$
DECLARE
  ts timestamptz := '2024-01-01 10:15+00';
BEGIN
  PERFORM audit_eq('unfiltered',
    tci.count_at('audit_sessions'::regclass, ts),
    (SELECT count(*) FROM audit_sessions s
      WHERE started_at <= ts AND (ended_at IS NULL OR ended_at > ts)));
  PERFORM audit_eq('enterprise',
    tci.count_at_filtered('audit_sessions'::regclass, ts, 'segment', 'enterprise'),
    (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
       AND started_at <= ts AND (ended_at IS NULL OR ended_at > ts)));
  PERFORM audit_eq('null_seg',
    tci.count_at_filtered('audit_sessions'::regclass, ts, 'segment', NULL),
    (SELECT count(*) FROM audit_sessions WHERE segment IS NULL
       AND started_at <= ts AND (ended_at IS NULL OR ended_at > ts)));
  PERFORM audit_eq('quoted',
    tci.count_at_filtered('audit_sessions'::regclass, ts, 'segment', 'weird''quote'),
    (SELECT count(*) FROM audit_sessions WHERE segment = 'weird''quote'
       AND started_at <= ts AND (ended_at IS NULL OR ended_at > ts)));
  PERFORM audit_eq('region1',
    tci.count_at_filtered('audit_sessions'::regclass, ts, 'region', '1'),
    (SELECT count(*) FROM audit_sessions WHERE region = 1
       AND started_at <= ts AND (ended_at IS NULL OR ended_at > ts)));
END $$;

-- INSERT / UPDATE times / UPDATE filter / both / unrelated / DELETE
INSERT INTO audit_sessions(segment, region, started_at, ended_at)
VALUES ('enterprise', 1, '2024-01-01 10:05+00', '2024-01-01 10:50+00');
SELECT audit_eq('after_insert',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

UPDATE audit_sessions SET ended_at = '2024-01-01 10:20+00'
 WHERE id = (SELECT min(id) FROM audit_sessions WHERE segment='enterprise');
SELECT audit_eq('after_upd_end',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:30+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:30+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:30+00')));

UPDATE audit_sessions SET segment = 'smb'
 WHERE id = (SELECT min(id) FROM audit_sessions WHERE segment='enterprise');
SELECT audit_eq('after_move_e',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));
SELECT audit_eq('after_move_s',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb'),
  (SELECT count(*) FROM audit_sessions WHERE segment='smb'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

UPDATE audit_sessions SET started_at = started_at - interval '1 minute', segment = 'enterprise'
 WHERE id = (SELECT max(id) FROM audit_sessions WHERE segment='smb');
SELECT audit_eq('after_both',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

UPDATE audit_sessions SET note = 'touched' WHERE id = 2;
SELECT audit_eq('unrelated_col',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));
SELECT audit_eq('unrelated_unf',
  tci.count_at('audit_sessions'::regclass, '2024-01-01 10:15+00'),
  (SELECT count(*) FROM audit_sessions s
    WHERE started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

DELETE FROM audit_sessions WHERE note = 'c';
SELECT audit_eq('after_delete',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb'),
  (SELECT count(*) FROM audit_sessions WHERE segment='smb'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

-- Rollback / savepoint
BEGIN;
INSERT INTO audit_sessions(segment, region, started_at, ended_at)
VALUES ('enterprise', 1, '2024-01-01 10:10+00', NULL);
SAVEPOINT sp1;
UPDATE audit_sessions SET segment='smb' WHERE id = (SELECT max(id) FROM audit_sessions);
ROLLBACK TO sp1;
SELECT audit_eq('in_txn_after_sp',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));
ROLLBACK;
SELECT audit_eq('after_rollback',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

-- Seal batch-id + maintain
SELECT tci.seal_filtered('audit_sessions'::regclass, 'segment', 'enterprise', 8192);
SELECT * FROM tci.maintain_filters('audit_sessions'::regclass, 1, 2);
SELECT audit_eq('after_seal',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise'),
  (SELECT count(*) FROM audit_sessions WHERE segment='enterprise'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

-- Rebuild / invalidate
SELECT tci.invalidate_filtered('audit_sessions'::regclass, 'segment', 'smb');
-- invalid → native fallback must still match
SELECT audit_eq('invalid_fallback',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb'),
  (SELECT count(*) FROM audit_sessions WHERE segment='smb'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));
SELECT tci.rebuild_filtered('audit_sessions'::regclass, 'segment', 'smb');
SELECT audit_eq('after_rebuild',
  tci.count_at_filtered('audit_sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb'),
  (SELECT count(*) FROM audit_sessions WHERE segment='smb'
     AND started_at <= '2024-01-01 10:15+00' AND (ended_at IS NULL OR ended_at > '2024-01-01 10:15+00')));

-- Unregistered
DO $$
BEGIN
  PERFORM tci.count_at_filtered('audit_sessions'::regclass, now(), 'segment', 'ghost');
  RAISE EXCEPTION 'FAIL unregistered should error';
EXCEPTION WHEN OTHERS THEN
  IF SQLERRM LIKE 'pg_tci: no filtered index%' THEN
    RAISE NOTICE 'PASS unregistered_error';
  ELSE
    RAISE;
  END IF;
END $$;

-- Bad type
DO $$
BEGIN
  PERFORM tci.create_filtered('audit_sessions'::regclass, 'started_at', 'ended_at', 'region', 'not-an-int');
  RAISE EXCEPTION 'FAIL bad type should error';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'PASS bad_type_error: %', SQLERRM;
END $$;

-- Partitioned rejected
CREATE TABLE part_sess (
  id bigserial,
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  PRIMARY KEY (id, started_at)
) PARTITION BY RANGE (started_at);
DO $$
BEGIN
  PERFORM tci.create('part_sess'::regclass, 'started_at', 'ended_at');
  RAISE EXCEPTION 'FAIL partition should reject';
EXCEPTION WHEN OTHERS THEN
  IF SQLERRM LIKE '%partition%' THEN
    RAISE NOTICE 'PASS partition_rejected';
  ELSE
    RAISE;
  END IF;
END $$;
DROP TABLE part_sess;

-- Drop filter cleanup
SELECT tci.drop_filtered('audit_sessions'::regclass, 'segment', 'weird''quote');
DO $$
BEGIN
  PERFORM tci.count_at_filtered('audit_sessions'::regclass, now(), 'segment', 'weird''quote');
  RAISE EXCEPTION 'FAIL drop should unregister';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'PASS drop_filtered';
END $$;

SELECT 'AUDIT_CORE_DONE' AS status;
