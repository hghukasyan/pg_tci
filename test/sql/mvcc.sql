-- MVCC / snapshot discipline + fail-closed paths for pg_tci 0.1.8
CREATE EXTENSION pg_tci;

CREATE TABLE mvcc_sessions (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO mvcc_sessions(started_at, ended_at) VALUES
  ('2024-06-01 10:00+00', '2024-06-01 12:00+00'),
  ('2024-06-01 11:00+00', NULL);

SELECT tci.create('mvcc_sessions'::regclass, 'started_at', 'ended_at') > 0 AS created;

-- Same-snapshot exactness under REPEATABLE READ
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT tci.count_at('mvcc_sessions', timestamptz '2024-06-01 11:30+00') AS tci_c;
SELECT count(*) AS native_c FROM mvcc_sessions s
 WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
COMMIT;

-- Tail delta visible under same snapshot after insert
BEGIN ISOLATION LEVEL REPEATABLE READ;
INSERT INTO mvcc_sessions(started_at, ended_at)
VALUES ('2024-06-01 11:15+00', '2024-06-01 11:45+00');
SELECT tci.count_at('mvcc_sessions', timestamptz '2024-06-01 11:30+00') AS tci_tail;
SELECT count(*) AS native_tail FROM mvcc_sessions s
 WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
COMMIT;

SELECT tci.seal_bounded('mvcc_sessions', 8192) IS NOT NULL AS sealed;

BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT tci.count_at('mvcc_sessions', timestamptz '2024-06-01 11:30+00') AS tci_sealed;
SELECT count(*) AS native_sealed FROM mvcc_sessions s
 WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
COMMIT;

-- Fail closed: invalidate → native path still matches
SELECT tci.invalidate('mvcc_sessions');
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT (tci.stats('mvcc_sessions')).valid AS is_valid;
SELECT tci.count_at('mvcc_sessions', timestamptz '2024-06-01 11:30+00') AS tci_inv;
SELECT count(*) AS native_inv FROM mvcc_sessions s
 WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
   AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
COMMIT;

SELECT tci.rebuild('mvcc_sessions');
SELECT (tci.health('mvcc_sessions')).published AS healthy_published,
       (tci.health('mvcc_sessions')).valid AS healthy_valid;

DROP EXTENSION pg_tci CASCADE;
DROP TABLE mvcc_sessions;
