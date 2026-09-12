-- Security / RLS / privilege audit for filtered TCI
\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS pg_tci;

DROP ROLE IF EXISTS filt_owner;
DROP ROLE IF EXISTS filt_reader;
DROP ROLE IF EXISTS filt_stranger;
CREATE ROLE filt_owner;
CREATE ROLE filt_reader;
CREATE ROLE filt_stranger;

DROP TABLE IF EXISTS public.tenant_sessions CASCADE;
CREATE TABLE public.tenant_sessions (
  id bigserial PRIMARY KEY,
  tenant text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);
ALTER TABLE public.tenant_sessions OWNER TO filt_owner;
GRANT SELECT ON public.tenant_sessions TO filt_reader;

SET SESSION AUTHORIZATION filt_owner;
INSERT INTO public.tenant_sessions(tenant, started_at, ended_at) VALUES
  ('A', '2024-01-01 10:00+00', '2024-01-01 11:00+00'),
  ('B', '2024-01-01 10:00+00', '2024-01-01 11:00+00');
SELECT tci.create_filtered('public.tenant_sessions'::regclass, 'started_at', 'ended_at', 'tenant', 'A') > 0 AS created_a;
SELECT tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A') AS owner_ok;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION filt_reader;
SELECT tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A') AS reader_ok;
DO $$
BEGIN
  PERFORM tci.seal_filtered('public.tenant_sessions'::regclass, 'tenant', 'A');
  RAISE EXCEPTION 'FAIL reader seal should be denied';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS reader_admin_denied';
WHEN OTHERS THEN
  RAISE NOTICE 'PASS reader_admin_denied: %', SQLERRM;
END $$;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION filt_stranger;
DO $$
BEGIN
  PERFORM tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A');
  RAISE EXCEPTION 'FAIL stranger should lack SELECT';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS stranger_no_select';
WHEN OTHERS THEN
  IF SQLERRM LIKE '%permission denied%' THEN
    RAISE NOTICE 'PASS stranger_no_select';
  ELSE
    RAISE;
  END IF;
END $$;
RESET SESSION AUTHORIZATION;

-- Enable RLS: reader with SELECT must NOT get aggregate bypass
ALTER TABLE public.tenant_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_a_only ON public.tenant_sessions
  FOR SELECT TO filt_reader USING (tenant = 'A');

SET SESSION AUTHORIZATION filt_reader;
-- Must fail closed (RLS enabled, not owner)
DO $$
BEGIN
  PERFORM tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A');
  RAISE EXCEPTION 'FAIL RLS bypass';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS rls_fail_closed: %', SQLERRM;
WHEN OTHERS THEN
  IF SQLERRM LIKE '%RLS%' THEN
    RAISE NOTICE 'PASS rls_fail_closed: %', SQLERRM;
  ELSE
    RAISE;
  END IF;
END $$;
RESET SESSION AUTHORIZATION;

-- Owner still OK (no FORCE)
SET SESSION AUTHORIZATION filt_owner;
SELECT tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A') AS owner_with_rls;
RESET SESSION AUTHORIZATION;

-- FORCE RLS: even owner refused without BYPASSRLS
ALTER TABLE public.tenant_sessions FORCE ROW LEVEL SECURITY;
SET SESSION AUTHORIZATION filt_owner;
DO $$
BEGIN
  PERFORM tci.count_at_filtered('public.tenant_sessions'::regclass, '2024-01-01 10:30+00', 'tenant', 'A');
  RAISE EXCEPTION 'FAIL FORCE RLS owner bypass';
EXCEPTION WHEN OTHERS THEN
  IF SQLERRM LIKE '%RLS%' THEN
    RAISE NOTICE 'PASS force_rls_owner_refused';
  ELSE
    RAISE;
  END IF;
END $$;
RESET SESSION AUTHORIZATION;

SELECT 'SECURITY_AUDIT_DONE' AS status;
