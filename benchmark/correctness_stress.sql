-- Correctness evidence harness (NOT a formal MVCC proof).
-- Same-snapshot TCI vs native under REPEATABLE READ, with light writes between checks.
--
-- Usage:
--   createdb tci_stress && psql -d tci_stress -c "CREATE EXTENSION pg_tci"
--   psql -d tci_stress -v ON_ERROR_STOP=1 -f benchmark/correctness_stress.sql

\set ON_ERROR_STOP on

DROP TABLE IF EXISTS stress_sessions CASCADE;
CREATE TABLE stress_sessions (
  id bigserial PRIMARY KEY,
  segment text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO stress_sessions(segment, started_at, ended_at)
SELECT (ARRAY['a','b','c','d'])[1 + (g % 4)],
       timestamptz '2024-01-01' + ((g % 500) || ' minutes')::interval,
       CASE WHEN random() < 0.2 THEN NULL
            ELSE timestamptz '2024-01-01'
                 + (((g % 500) + 20 + (random()*40)::int) || ' minutes')::interval
       END
FROM generate_series(1, 20000) g;

SELECT tci.create('stress_sessions'::regclass, 'started_at', 'ended_at') > 0 AS created_u;
SELECT tci.create_filtered(
  'stress_sessions'::regclass, 'started_at', 'ended_at', 'segment', 'a') > 0 AS created_f;

SELECT * FROM tci.maintain('stress_sessions'::regclass, 1000, 8, 5000, 8, 5000, true, 'pairwise');
SELECT * FROM tci.maintain_filters('stress_sessions'::regclass, 1000, 8);

CREATE TEMP TABLE stress_mismatches (
  i int,
  probe timestamptz,
  tci_u bigint,
  nat_u bigint,
  tci_f bigint,
  nat_f bigint
);

DO $$
DECLARE
  i int;
  probe timestamptz;
  tci_u bigint;
  nat_u bigint;
  tci_f bigint;
  nat_f bigint;
BEGIN
  FOR i IN 1..50 LOOP
    probe := timestamptz '2024-01-01' + ((i * 11) || ' minutes')::interval;

    INSERT INTO stress_sessions(segment, started_at, ended_at)
    VALUES ('a', probe - interval '5 minutes', probe + interval '30 minutes');

    IF i % 5 = 0 THEN
      PERFORM 1 FROM tci.maintain(
        'stress_sessions'::regclass, 500, 8, 2000, 4, 2000, true, 'pairwise');
    END IF;

    -- Paired reads share this DO-block transaction's snapshot
    tci_u := tci.count_at('stress_sessions'::regclass, probe);
    SELECT count(*) INTO nat_u FROM stress_sessions s
     WHERE s.started_at <= probe AND (s.ended_at IS NULL OR s.ended_at > probe);
    tci_f := tci.count_at_filtered('stress_sessions'::regclass, probe, 'segment', 'a');
    SELECT count(*) INTO nat_f FROM stress_sessions s
     WHERE s.segment = 'a'
       AND s.started_at <= probe AND (s.ended_at IS NULL OR s.ended_at > probe);

    IF tci_u IS DISTINCT FROM nat_u OR tci_f IS DISTINCT FROM nat_f THEN
      INSERT INTO stress_mismatches VALUES (i, probe, tci_u, nat_u, tci_f, nat_f);
    END IF;
  END LOOP;
END $$;

SELECT count(*) AS mismatch_rows FROM stress_mismatches;
SELECT * FROM stress_mismatches ORDER BY i LIMIT 20;

DO $$
DECLARE
  n int;
BEGIN
  SELECT count(*) INTO n FROM stress_mismatches;
  IF n > 0 THEN
    RAISE EXCEPTION 'correctness_stress FAILED: % mismatches (see stress_mismatches)', n;
  END IF;
  RAISE NOTICE 'correctness_stress PASS: 50 paired checks in one snapshot + writers';
END $$;
