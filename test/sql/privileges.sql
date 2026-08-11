-- Privilege tests for pg_tci 0.1.8 (ACL + session_user gates)
-- Use SESSION AUTHORIZATION so SECURITY DEFINER checks see the right identity.
CREATE EXTENSION pg_tci;

CREATE ROLE tci_owner;
CREATE ROLE tci_reader;
CREATE ROLE tci_stranger;

CREATE TABLE public.owner_sessions (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);
ALTER TABLE public.owner_sessions OWNER TO tci_owner;
GRANT SELECT ON public.owner_sessions TO tci_reader;
-- stranger: no grants

SET SESSION AUTHORIZATION tci_owner;
INSERT INTO public.owner_sessions(started_at, ended_at)
VALUES (timestamptz '2024-01-01 10:00+00', timestamptz '2024-01-01 11:00+00');
SELECT tci.create('public.owner_sessions'::regclass, 'started_at', 'ended_at') > 0 AS created;
SELECT tci.count_at('public.owner_sessions'::regclass, timestamptz '2024-01-01 10:30+00') AS owner_count;
-- Owner received admin EXECUTE via create()
SELECT tci.seal_bounded('public.owner_sessions'::regclass, 8192) IS NULL AS owner_seal_empty_ok;
SELECT (tci.health('public.owner_sessions'::regclass)).index_id IS NOT NULL AS owner_health;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION tci_reader;
SELECT tci.count_at('public.owner_sessions'::regclass, timestamptz '2024-01-01 10:30+00') AS reader_count;
SELECT (tci.health('public.owner_sessions'::regclass)).n_tail IS NOT NULL AS reader_health;
-- Admin APIs: no PUBLIC EXECUTE → permission denied (ACL), not require_admin body
SELECT tci.seal('public.owner_sessions'::regclass); -- fail: no EXECUTE
SELECT tci.compact_pairwise('public.owner_sessions'::regclass); -- fail: no EXECUTE
SELECT tci.maint_history('public.owner_sessions'::regclass); -- fail: no EXECUTE
SELECT (tci.capacity('public.owner_sessions'::regclass)).index_id IS NOT NULL AS reader_capacity;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION tci_stranger;
SELECT tci.count_at('public.owner_sessions'::regclass, timestamptz '2024-01-01 10:30+00'); -- fail: no SELECT
SELECT tci.shard_stats('public.owner_sessions'::regclass); -- fail: no SELECT
SELECT tci.health('public.owner_sessions'::regclass); -- fail: no SELECT
RESET SESSION AUTHORIZATION;

DROP EXTENSION pg_tci CASCADE;
DROP TABLE public.owner_sessions;
DROP ROLE tci_stranger;
DROP ROLE tci_reader;
DROP ROLE tci_owner;
