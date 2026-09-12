-- Native filtered TCI example (pg_tci 0.1.11)
CREATE EXTENSION IF NOT EXISTS pg_tci;

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  segment text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO sessions(segment, started_at, ended_at) VALUES
  ('enterprise', now() - interval '2 hours', now() + interval '1 hour'),
  ('enterprise', now() - interval '30 minutes', NULL),
  ('smb', now() - interval '1 hour', now() + interval '30 minutes');

SELECT tci.create_filtered(
  'sessions'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise');
SELECT tci.create_filtered(
  'sessions'::regclass, 'started_at', 'ended_at', 'segment', 'smb');

SELECT tci.count_at_filtered('sessions'::regclass, now(), 'segment', 'enterprise');
SELECT tci.count_at_filtered('sessions'::regclass, now(), 'segment', 'smb');

-- Filter move
UPDATE sessions SET segment = 'smb' WHERE id = 1;
SELECT tci.count_at_filtered('sessions'::regclass, now(), 'segment', 'enterprise');
SELECT tci.count_at_filtered('sessions'::regclass, now(), 'segment', 'smb');

-- Optional: unfiltered index may coexist
-- SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at');
-- SELECT tci.count_at('sessions'::regclass, now());

SELECT * FROM tci.list_filters('sessions'::regclass);
SELECT * FROM tci.maintain_filters('sessions'::regclass);
SELECT * FROM tci.storage_bytes('sessions'::regclass);

-- Unregistered filter → ERROR
-- SELECT tci.count_at_filtered('sessions'::regclass, now(), 'segment', 'ghost');
