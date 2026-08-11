# Seal running concurrently with a REPEATABLE READ reader must not break
# same-snapshot equality between tci.count_at and native COUNT.
setup
{
  CREATE TABLE iso_seal (
    id bigserial PRIMARY KEY,
    started_at timestamptz NOT NULL,
    ended_at timestamptz
  );
  INSERT INTO iso_seal(started_at, ended_at) VALUES
    ('2024-06-01 10:00+00', '2024-06-01 12:00+00'),
    ('2024-06-01 11:00+00', NULL),
    ('2024-06-01 11:10+00', '2024-06-01 11:50+00');
  SELECT tci.create('iso_seal'::regclass, 'started_at', 'ended_at');
  -- Leave a small tail so seal_bounded has work (or no-ops cleanly).
  INSERT INTO iso_seal(started_at, ended_at)
  VALUES ('2024-06-01 11:20+00', '2024-06-01 11:40+00');
}

teardown
{
  DROP TABLE iso_seal CASCADE;
}

session s1
setup		{ BEGIN ISOLATION LEVEL REPEATABLE READ; }
step s1c	{
  SELECT tci.count_at('iso_seal', timestamptz '2024-06-01 11:30+00') AS tci_c;
}
step s1n	{
  SELECT count(*) AS native_c FROM iso_seal s
   WHERE s.started_at <= timestamptz '2024-06-01 11:30+00'
     AND (s.ended_at IS NULL OR s.ended_at > timestamptz '2024-06-01 11:30+00');
}
step s1x	{ COMMIT; }

session s2
step s2seal	{
  SELECT tci.seal_bounded('iso_seal', 8192) IS NOT NULL AS sealed;
}

permutation s1c s2seal s1n s1x
permutation s2seal s1c s1n s1x
