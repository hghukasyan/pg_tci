# Concurrent INSERT under REPEATABLE READ must not change an already-open
# snapshot's tci.count_at vs native COUNT.
setup
{
  CREATE TABLE iso_sessions (
    id bigserial PRIMARY KEY,
    started_at timestamptz NOT NULL,
    ended_at timestamptz
  );
  INSERT INTO iso_sessions(started_at, ended_at) VALUES
    ('2024-06-01 10:00+00', '2024-06-01 12:00+00'),
    ('2024-06-01 11:00+00', NULL);
  SELECT tci.create('iso_sessions'::regclass, 'started_at', 'ended_at');
}

teardown
{
  DROP TABLE iso_sessions CASCADE;
}

session s1
setup		{ BEGIN ISOLATION LEVEL REPEATABLE READ; }
step s1c	{
  SELECT tci.count_at('iso_sessions', timestamptz '2024-06-01 11:30+00') AS tci_c;
}
step s1n	{
  SELECT count(*) AS native_c FROM iso_sessions s
   WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
     AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
}
step s1x	{ COMMIT; }

session s2
step s2i	{
  INSERT INTO iso_sessions(started_at, ended_at)
  VALUES ('2024-06-01 11:15+00', '2024-06-01 11:45+00');
}

# s1 opens RR, counts, then s2 inserts; s1 native must still match tci (both 2).
permutation s1c s2i s1n s1x
# Insert before s1's native check but after tci count — still same snapshot.
permutation s1c s1n s2i s1x
