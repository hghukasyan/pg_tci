-- basic regression for pg_tci 0.1.0-preview
CREATE EXTENSION pg_tci;

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO sessions(started_at, ended_at) VALUES
  ('2024-01-01 10:00+00', '2024-01-01 11:00+00'),
  ('2024-01-01 10:30+00', '2024-01-01 12:00+00'),
  ('2024-01-01 11:00+00', NULL);

SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at');

SELECT tci.count_at('sessions'::regclass, '2024-01-01 10:15+00') AS c1;
SELECT count(*) FROM sessions s
 WHERE s.started_at <= '2024-01-01 10:15+00'
   AND (s.ended_at IS NULL OR s.ended_at > '2024-01-01 10:15+00');

SELECT tci.count_at('sessions'::regclass, '2024-01-01 11:30+00') AS c2;

INSERT INTO sessions(started_at, ended_at)
VALUES ('2024-01-01 11:15+00', '2024-01-01 11:45+00');

SELECT tci.count_at('sessions'::regclass, '2024-01-01 11:30+00') AS c3_with_tail;

SELECT tci.seal('sessions'::regclass) IS NOT NULL AS sealed;

SELECT (tci.stats('sessions'::regclass)).live_runs,
       (tci.stats('sessions'::regclass)).n_tail;

-- codec smoke
SELECT tci_internal.chunk_prefix_at(
  tci_internal.pack_entries(ARRAY[100,200]::bigint[], ARRAY[1,-1]::smallint[], 32),
  100) AS pref;

SELECT tci_internal.pack_validate(
  tci_internal.pack_entries(ARRAY[1]::bigint[], ARRAY[1]::smallint[], 64));

DROP EXTENSION pg_tci CASCADE;
DROP TABLE sessions;
