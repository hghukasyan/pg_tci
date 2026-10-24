-- 0.1.12: count_at_safe under RLS → native; packed count_at refuses
-- Use SET SESSION AUTHORIZATION so session_user matches (gates use session_user).
CREATE EXTENSION pg_tci;

DROP ROLE IF EXISTS tci_rls_reader;
DROP ROLE IF EXISTS tci_rls_owner;
CREATE ROLE tci_rls_owner LOGIN;
CREATE ROLE tci_rls_reader LOGIN;

CREATE TABLE rls_sess (
  id bigserial PRIMARY KEY,
  owner_name text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

ALTER TABLE rls_sess OWNER TO tci_rls_owner;
GRANT SELECT ON rls_sess TO tci_rls_reader;

INSERT INTO rls_sess(owner_name, started_at, ended_at) VALUES
  ('alice', '2024-01-01 10:00+00', '2024-01-01 12:00+00'),
  ('bob', '2024-01-01 10:00+00', '2024-01-01 12:00+00');

SET SESSION AUTHORIZATION tci_rls_owner;
SELECT tci.create('rls_sess'::regclass, 'started_at', 'ended_at') > 0 AS created;
ALTER TABLE rls_sess ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_sess_own ON rls_sess
  FOR SELECT TO tci_rls_reader
  USING (owner_name = 'alice');
-- Owner also subject to RLS for reader policy testing: FORCE so owner packed path
-- is not under test here; reader is the refuse case.
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION tci_rls_reader;
\set VERBOSITY terse
SELECT tci.count_at('rls_sess'::regclass, '2024-01-01 11:00+00');
\set VERBOSITY default
SELECT tci.count_at_safe('rls_sess'::regclass, '2024-01-01 11:00+00') AS safe_n;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION tci_rls_owner;
SELECT tci.count_at('rls_sess'::regclass, '2024-01-01 11:00+00') AS owner_n;
SELECT tci.count_at_safe('rls_sess'::regclass, '2024-01-01 11:00+00') AS owner_safe;
RESET SESSION AUTHORIZATION;

DROP EXTENSION pg_tci CASCADE;
DROP TABLE rls_sess;
DROP ROLE tci_rls_reader;
DROP ROLE tci_rls_owner;
