-- Native filtered TCI regression (0.1.9)
CREATE EXTENSION pg_tci;

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  segment text,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO sessions(segment, started_at, ended_at) VALUES
  ('enterprise', '2024-01-01 10:00+00', '2024-01-01 11:00+00'),
  ('enterprise', '2024-01-01 10:30+00', '2024-01-01 12:00+00'),
  ('smb', '2024-01-01 10:00+00', '2024-01-01 12:00+00'),
  (NULL, '2024-01-01 10:00+00', '2024-01-01 11:00+00');

SELECT tci.create_filtered('sessions'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise') > 0 AS created_e;
SELECT tci.create_filtered('sessions'::regclass, 'started_at', 'ended_at', 'segment', 'smb') > 0 AS created_s;
SELECT tci.create_filtered('sessions'::regclass, 'started_at', 'ended_at', 'segment', NULL) > 0 AS created_n;

SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise') AS e;
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb') AS s;
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', NULL) AS n;

-- INSERT / move / DELETE
INSERT INTO sessions(segment, started_at, ended_at)
VALUES ('enterprise', '2024-01-01 10:05+00', '2024-01-01 10:50+00');
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise') AS e2;

UPDATE sessions SET segment = 'smb' WHERE id = 1;
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'enterprise') AS e3;
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb') AS s3;

DELETE FROM sessions WHERE id = 3;
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'smb') AS s4;

-- Unregistered filter errors (never silent fallback to another index)
\set VERBOSITY terse
SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 10:15+00', 'segment', 'ghost');

DROP EXTENSION pg_tci CASCADE;
DROP TABLE sessions;
