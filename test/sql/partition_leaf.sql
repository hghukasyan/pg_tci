-- 0.1.11: partition parents rejected; leaves allowed
CREATE EXTENSION pg_tci;

CREATE TABLE sess_p (
  id bigserial,
  segment text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  PRIMARY KEY (id, started_at)
) PARTITION BY RANGE (started_at);

CREATE TABLE sess_p_2024 PARTITION OF sess_p
  FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');

INSERT INTO sess_p(segment, started_at, ended_at) VALUES
  ('enterprise', '2024-06-01 10:00+00', '2024-06-01 12:00+00'),
  ('smb', '2024-06-01 11:00+00', NULL);

-- Parent must fail
\set VERBOSITY terse
SELECT tci.create('sess_p'::regclass, 'started_at', 'ended_at');

-- Leaf OK
\set VERBOSITY default
SELECT tci.create('sess_p_2024'::regclass, 'started_at', 'ended_at') > 0 AS leaf_ok;
SELECT tci.create_filtered(
  'sess_p_2024'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise') > 0 AS leaf_filt;

SELECT tci.count_at('sess_p_2024'::regclass, '2024-06-01 11:30+00') AS c_unf;
SELECT tci.count_at_filtered(
  'sess_p_2024'::regclass, '2024-06-01 11:30+00', 'segment', 'enterprise') AS c_filt;

DROP EXTENSION pg_tci CASCADE;
DROP TABLE sess_p;
