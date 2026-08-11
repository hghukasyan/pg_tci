-- pg_tci 0.1.7 → 0.1.8
-- Production hardening: admin EXECUTE ACL, grant helpers, health/maint history,
-- create() auto-grants admin EXECUTE to table owner.

-- ---------------------------------------------------------------------------
-- Admin EXECUTE grant/revoke helpers (defense in depth vs PUBLIC DEFINER invoke)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.admin_procedures()
RETURNS SETOF regprocedure
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.oid::regprocedure
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'tci'
    AND p.proname = ANY (ARRAY[
      'seal', 'seal_bounded', 'compact', 'compact_pairwise', 'compact_budget',
      'maintain', 'invalidate', 'rebuild', 'capacity_reset', 'set_shard_count',
      'maint_history'
    ]);
$$;

CREATE OR REPLACE FUNCTION tci_internal.grant_admin_execute(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  fp regprocedure;
BEGIN
  IF to_regrole(target_role) IS NULL THEN
    RAISE EXCEPTION 'pg_tci: role % does not exist', target_role;
  END IF;
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', fp, target_role);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.revoke_admin_execute(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  fp regprocedure;
BEGIN
  IF to_regrole(target_role) IS NULL THEN
    RAISE EXCEPTION 'pg_tci: role % does not exist', target_role;
  END IF;
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I', fp, target_role);
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci.grant_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: grant_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.grant_admin_execute(target_role);
  -- Also allow bootstrap create for that role.
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO %I',
    target_role);
END;
$$;

CREATE OR REPLACE FUNCTION tci.revoke_admin(target_role name)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user, 'pg_database_owner', 'MEMBER')
     AND NOT EXISTS (
       SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper
     ) THEN
    RAISE EXCEPTION 'pg_tci: revoke_admin requires superuser or database owner'
      USING ERRCODE = '42501';
  END IF;
  PERFORM tci_internal.revoke_admin_execute(target_role);
  EXECUTE format(
    'REVOKE ALL ON FUNCTION tci.create(regclass, name, name, int, int, name, int) FROM %I',
    target_role);
END;
$$;

REVOKE ALL ON FUNCTION tci_internal.admin_procedures() FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.grant_admin_execute(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.revoke_admin_execute(name) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- create(): after rebuild, grant admin EXECUTE to table owner
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create(
  source_table regclass,
  start_col name,
  end_col name,
  chunk_bytes int DEFAULT 8192,
  cp_interval int DEFAULT 64,
  id_col name DEFAULT 'id',
  shard_count int DEFAULT 1
) RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  nsp name;
  rel name;
  start_ty oid;
  end_ty oid;
  idx_id int;
  owner_name name;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname, r.rolname
    INTO nsp, rel, owner_name
  FROM pg_class c
  JOIN pg_roles r ON r.oid = c.relowner
  WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_col AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_col, end_col;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF EXISTS (SELECT 1 FROM tci_internal.indexes WHERE source_oid = source_table) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes WHERE source_nsp = nsp AND source_rel = rel
  ) THEN
    RAISE EXCEPTION 'pg_tci: stale catalog entry for %.% — drop/invalidate first', nsp, rel;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid)
  VALUES (
    source_table, nsp, rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, false, true)
  RETURNING index_id INTO idx_id;

  EXECUTE format(
    'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
     FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
    source_table);

  PERFORM tci.rebuild(source_table);

  -- Owner can maintain without PUBLIC EXECUTE on admin DEFINER APIs.
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Monitoring: health + maint_history
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.health(source_table regclass)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  published boolean,
  valid boolean,
  shard_count int,
  generation bigint,
  n_tail bigint,
  live_runs int,
  deltas_sealed bigint,
  deltas_sealed_per_sec double precision,
  deltas_ingested bigint,
  deltas_ingested_per_sec double precision,
  last_seal_at timestamptz,
  seconds_since_reset double precision,
  capacity_ok boolean,
  detail text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  idx := tci_internal.relink_source(source_table);
  -- Inline insert (not ensure_cap SQL fn) so CCI makes the row visible to
  -- RETURN QUERY in this same PL/pgSQL call.
  INSERT INTO tci_internal.cap_counters(index_id)
  SELECT idx.index_id
   WHERE NOT EXISTS (
     SELECT 1 FROM tci_internal.cap_counters c WHERE c.index_id = idx.index_id
   );

  RETURN QUERY
  SELECT
    i.index_id,
    format('%I.%I', i.source_nsp, i.source_rel)::text,
    i.published,
    i.valid,
    i.shard_count,
    i.generation,
    (SELECT count(*) FROM tci_internal.tail t
      WHERE t.index_id = i.index_id AND t.generation = i.generation),
    (SELECT count(*)::int FROM tci_internal.runs r
      WHERE r.index_id = i.index_id AND r.status = 'live'),
    c.deltas_sealed,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_sealed / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.deltas_ingested,
    CASE WHEN EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 0
         THEN (c.deltas_ingested / EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)))::float8
         ELSE 0::float8 END,
    c.last_seal_at,
    EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at))::float8,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN false
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
           AND EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 60
           AND (c.deltas_sealed / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1))
               < (c.deltas_ingested / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1)) * 0.5
        THEN false
      ELSE true
    END,
    CASE
      WHEN NOT i.valid OR NOT i.published THEN 'invalid_or_unpublished'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
        THEN 'tail_large'::text
      ELSE NULL::text
    END
  FROM tci_internal.indexes i
  JOIN tci_internal.cap_counters c ON c.index_id = i.index_id
  WHERE i.index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.maint_history(
  source_table regclass,
  max_rows int DEFAULT 20
)
RETURNS TABLE (
  id bigint,
  op text,
  started_at timestamptz,
  duration_ms double precision,
  n_tail_before bigint,
  n_tail_after bigint,
  n_live_before int,
  n_live_after int,
  skipped_reason text,
  detail text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  lim int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_source(source_table);
  lim := GREATEST(COALESCE(max_rows, 20), 1);
  lim := LEAST(lim, 1000);

  RETURN QUERY
  SELECT m.id, m.op, m.started_at, m.duration_ms,
         m.n_tail_before, m.n_tail_after, m.n_live_before, m.n_live_after,
         m.skipped_reason, m.detail
  FROM tci_internal.maint_log m
  WHERE m.index_id = idx.index_id
  ORDER BY m.id DESC
  LIMIT lim;
END;
$$;

-- ---------------------------------------------------------------------------
-- Harden: revoke PUBLIC EXECUTE on admin DEFINER APIs (keep create for bootstrap)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  fp regprocedure;
BEGIN
  FOR fp IN SELECT * FROM tci_internal.admin_procedures() LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', fp);
  END LOOP;
END $$;

-- Read-path stays PUBLIC + require_select
GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.shard_stats(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.capacity(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.health(regclass) TO PUBLIC;

-- create remains PUBLIC for owner bootstrap (gated by require_admin)
GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO PUBLIC;

-- grant/revoke_admin: no PUBLIC; superuser/db owner only via body check
REVOKE ALL ON FUNCTION tci.grant_admin(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.revoke_admin(name) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maint_history(regclass, int) FROM PUBLIC;

COMMENT ON FUNCTION tci.grant_admin(name) IS
  'Grant EXECUTE on TCI admin APIs to a role (superuser/db owner).';
COMMENT ON FUNCTION tci.health(regclass) IS
  'Per-index capacity/health snapshot for monitoring.';
COMMENT ON FUNCTION tci.maint_history(regclass, int) IS
  'Recent seal/compact/maintain log rows for an index (admin).';

-- Existing indexes: grant admin EXECUTE to current table owners after revoke.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT roles.rolname AS rolname
    FROM tci_internal.indexes i
    JOIN pg_class c ON c.oid = i.source_oid
    JOIN pg_roles roles ON roles.oid = c.relowner
  LOOP
    PERFORM tci_internal.grant_admin_execute(r.rolname);
  END LOOP;
END $$;
