-- pg_tci 0.1.7-preview — basic usage example
-- Semantics: coverage COUNT for [start_at, end_at); NULL end_at = open-ended.

CREATE EXTENSION IF NOT EXISTS pg_tci;

CREATE TABLE IF NOT EXISTS sessions (
  id         bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at   timestamptz
);

INSERT INTO sessions (started_at, ended_at) VALUES
  ('2024-06-01 09:00+00', '2024-06-01 10:00+00'),
  ('2024-06-01 09:30+00', '2024-06-01 11:00+00'),
  ('2024-06-01 10:00+00', NULL);

SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at');

-- Native equivalent (source of truth):
--   SELECT count(*) FROM sessions s
--    WHERE s.started_at <= $1
--      AND (s.ended_at IS NULL OR s.ended_at > $1);

SELECT tci.count_at('sessions'::regclass, timestamptz '2024-06-01 09:45+00');
SELECT * FROM tci.stats('sessions'::regclass);

-- Maintenance (external scheduler recommended under write load)
SELECT tci.seal_bounded('sessions'::regclass, 8192);
SELECT tci.compact_pairwise('sessions'::regclass);
SELECT * FROM tci.maintain('sessions'::regclass);
SELECT * FROM tci.capacity('sessions'::regclass);

-- Force native COUNT fallback
-- SELECT tci.invalidate('sessions'::regclass);
-- Full rebuild from source
-- SELECT tci.rebuild('sessions'::regclass);
