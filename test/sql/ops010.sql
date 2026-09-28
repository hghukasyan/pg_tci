-- 0.1.10 pilot-ops: list_invalid, rebuild_invalid, filter_fit_estimate
CREATE EXTENSION pg_tci;

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  segment text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO sessions(segment, started_at, ended_at)
SELECT (ARRAY['enterprise','smb','startup','consumer'])[1 + (g % 4)],
       '2024-01-01'::timestamptz + ((g % 100) || ' minutes')::interval,
       '2024-01-01'::timestamptz + (((g % 100) + 30) || ' minutes')::interval
FROM generate_series(1, 200) g;

ANALYZE sessions;

SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at') > 0 AS created_u;
SELECT tci.create_filtered('sessions'::regclass, 'started_at', 'ended_at', 'segment', 'enterprise') > 0 AS created_f;

SELECT hint IS NOT NULL AS has_hint
  FROM tci.filter_fit_estimate('sessions'::regclass, 'segment');

SELECT count(*) = 0 AS none_invalid FROM tci.list_invalid('sessions'::regclass);

-- Force invalid then rebuild_invalid
SELECT tci.invalidate('sessions'::regclass);
SELECT tci.invalidate_filtered('sessions'::regclass, 'segment', 'enterprise');
SELECT count(*) >= 1 AS some_invalid FROM tci.list_invalid('sessions'::regclass);

SELECT count(*) >= 1 AS rebuilt
  FROM tci.rebuild_invalid('sessions'::regclass);

SELECT count(*) = 0 AS cleared FROM tci.list_invalid('sessions'::regclass);

SELECT tci.count_at('sessions'::regclass, '2024-01-01 00:30+00') =
       (SELECT count(*) FROM sessions
         WHERE started_at <= '2024-01-01 00:30+00'
           AND (ended_at IS NULL OR ended_at > '2024-01-01 00:30+00')) AS match_u;

SELECT tci.count_at_filtered('sessions'::regclass, '2024-01-01 00:30+00', 'segment', 'enterprise') =
       (SELECT count(*) FROM sessions
         WHERE segment = 'enterprise'
           AND started_at <= '2024-01-01 00:30+00'
           AND (ended_at IS NULL OR ended_at > '2024-01-01 00:30+00')) AS match_f;

SELECT capacity_ok IS NOT NULL AND detail IS NOT NULL AS health_ok
  FROM tci.health('sessions'::regclass)
 LIMIT 1;

DROP EXTENSION pg_tci CASCADE;
DROP TABLE sessions;
