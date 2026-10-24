-- pg_tci 0.1.11 → 0.1.12
-- Technical closure: partition-parent fan-out, count_at*_safe (native under RLS),
-- no packed bypass of RLS; no Index AM / formal proof.

-- ---------------------------------------------------------------------------
-- Helpers: partition leaves + RLS probe
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.partition_leaf_oids(p_parent regclass)
RETURNS SETOF oid
LANGUAGE sql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
  WITH RECURSIVE tree AS (
    SELECT i.inhrelid AS relid
      FROM pg_inherits i
     WHERE i.inhparent = p_parent
    UNION ALL
    SELECT i.inhrelid
      FROM pg_inherits i
      JOIN tree t ON i.inhparent = t.relid
  )
  SELECT c.oid
    FROM tree t
    JOIN pg_class c ON c.oid = t.relid
   WHERE c.relkind = 'r'
     AND NOT EXISTS (
       SELECT 1 FROM pg_inherits i2 WHERE i2.inhparent = c.oid
     );
$$;

CREATE OR REPLACE FUNCTION tci_internal.require_partitioned_parent(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  kind "char";
BEGIN
  SELECT c.relkind INTO kind FROM pg_class c WHERE c.oid = p_source;
  IF kind IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', p_source;
  END IF;
  IF kind <> 'p' THEN
    RAISE EXCEPTION
      'pg_tci: % is not a partitioned parent (relkind=%); use create/count_at on heap/leaf, or create_partitioned on a parent',
      p_source, kind;
  END IF;
END;
$$;

-- True when packed DEFINER COUNT must not run (same rules as require_rls_ok).
-- SECURITY DEFINER: callable from INVOKER count_*_safe; only reads catalogs.
CREATE OR REPLACE FUNCTION tci_internal.rls_blocks_packed(p_source regclass)
RETURNS boolean
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  rls boolean;
  force_rls boolean;
  owner oid;
BEGIN
  SELECT c.relrowsecurity, c.relforcerowsecurity, c.relowner
    INTO rls, force_rls, owner
  FROM pg_class c WHERE c.oid = p_source;
  IF owner IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', p_source;
  END IF;
  IF NOT COALESCE(rls, false) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolbypassrls
  ) THEN
    RETURN false;
  END IF;
  IF NOT COALESCE(force_rls, false)
     AND pg_has_role(session_user, owner, 'MEMBER') THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.require_rls_ok(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF tci_internal.rls_blocks_packed(p_source) THEN
    RAISE EXCEPTION
      'pg_tci: RLS is enabled on % — packed TCI COUNT refused (fail closed). Use tci.count_at_safe / count_at_filtered_safe for native coverage under policies.',
      p_source
      USING ERRCODE = '42501';
  END IF;
END;
$$;

-- DEFINER helper: INVOKER count_at_safe cannot SELECT tci_internal
CREATE OR REPLACE FUNCTION tci_internal.unfiltered_time_cols(p_source regclass)
RETURNS TABLE (start_col name, end_col name)
LANGUAGE sql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
  SELECT i.start_col, i.end_col
    FROM tci_internal.indexes i
   WHERE i.source_oid = p_source AND i.filter_col IS NULL
   LIMIT 1;
$$;

REVOKE ALL ON FUNCTION tci_internal.partition_leaf_oids(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.require_partitioned_parent(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.rls_blocks_packed(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.unfiltered_time_cols(regclass) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- list_partition_leaves
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.list_partition_leaves(parent_table regclass)
RETURNS TABLE (
  leaf regclass,
  has_unfiltered boolean,
  n_filters int
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.require_select(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);
  RETURN QUERY
  SELECT l.oid::regclass,
         EXISTS (
           SELECT 1 FROM tci_internal.indexes i
            WHERE i.source_oid = l.oid AND i.filter_col IS NULL
         ),
         (SELECT count(*)::int FROM tci_internal.indexes i
           WHERE i.source_oid = l.oid AND i.filter_col IS NOT NULL)
    FROM tci_internal.partition_leaf_oids(parent_table) AS l(oid)
   ORDER BY 1;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.list_partition_leaves(regclass) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- create_partitioned / create_filtered_partitioned
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create_partitioned(
  parent_table regclass,
  start_col name,
  end_col name,
  chunk_bytes int DEFAULT 8192,
  cp_interval int DEFAULT 64,
  id_col name DEFAULT 'id',
  shard_count int DEFAULT 1
) RETURNS TABLE (
  leaf regclass,
  index_id int,
  action text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  existing int;
  new_id int;
BEGIN
  PERFORM tci_internal.require_admin(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);

  IF NOT EXISTS (SELECT 1 FROM tci_internal.partition_leaf_oids(parent_table)) THEN
    RAISE EXCEPTION 'pg_tci: partitioned parent % has no heap leaves', parent_table;
  END IF;

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    PERFORM tci_internal.require_admin(leaf_oid::regclass);
    SELECT i.index_id INTO existing
      FROM tci_internal.indexes i
     WHERE i.source_oid = leaf_oid AND i.filter_col IS NULL;
    IF existing IS NOT NULL THEN
      leaf := leaf_oid::regclass;
      index_id := existing;
      action := 'skipped_exists';
      RETURN NEXT;
    ELSE
      new_id := tci.create(
        leaf_oid::regclass, start_col, end_col,
        chunk_bytes, cp_interval, id_col, shard_count);
      leaf := leaf_oid::regclass;
      index_id := new_id;
      action := 'created';
      RETURN NEXT;
    END IF;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci.create_filtered_partitioned(
  parent_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,
  chunk_bytes int DEFAULT 8192,
  cp_interval int DEFAULT 64,
  id_col name DEFAULT 'id',
  shard_count int DEFAULT 1
) RETURNS TABLE (
  leaf regclass,
  index_id int,
  action text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  existing int;
  new_id int;
  typid oid;
  canon text;
  is_null boolean;
BEGIN
  PERFORM tci_internal.require_admin(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);

  IF NOT EXISTS (SELECT 1 FROM tci_internal.partition_leaf_oids(parent_table)) THEN
    RAISE EXCEPTION 'pg_tci: partitioned parent % has no heap leaves', parent_table;
  END IF;

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    PERFORM tci_internal.require_admin(leaf_oid::regclass);
    SELECT * FROM tci_internal.resolve_filter_value(
      leaf_oid::regclass, filter_column, filter_value)
      INTO typid, canon, is_null;

    SELECT i.index_id INTO existing
      FROM tci_internal.indexes i
     WHERE i.source_oid = leaf_oid
       AND i.filter_col = filter_column
       AND i.filter_is_null = is_null
       AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon);
    IF existing IS NOT NULL THEN
      leaf := leaf_oid::regclass;
      index_id := existing;
      action := 'skipped_exists';
      RETURN NEXT;
    ELSE
      new_id := tci.create_filtered(
        leaf_oid::regclass, start_column, end_column,
        filter_column, filter_value,
        chunk_bytes, cp_interval, id_col, shard_count);
      leaf := leaf_oid::regclass;
      index_id := new_id;
      action := 'created';
      RETURN NEXT;
    END IF;
  END LOOP;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.create_partitioned(regclass, name, name, int, int, name, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.create_filtered_partitioned(regclass, name, name, name, text, int, int, name, int) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- count_at_partitioned / count_at_filtered_partitioned
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.count_at_partitioned(
  parent_table regclass,
  ts timestamptz
) RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  total bigint := 0;
  missing text := '';
BEGIN
  PERFORM tci_internal.require_select(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);
  -- RLS on parent: use same refuse as packed (caller should use safe on leaves)
  PERFORM tci_internal.require_rls_ok(parent_table);

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM tci_internal.indexes i
       WHERE i.source_oid = leaf_oid AND i.filter_col IS NULL AND i.published
    ) THEN
      missing := missing || format('%s ', leaf_oid::regclass);
    END IF;
  END LOOP;
  IF missing <> '' THEN
    RAISE EXCEPTION
      'pg_tci: missing unfiltered TCI on leaf(s): %— run tci.create_partitioned(%)',
      missing, parent_table;
  END IF;

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    total := total + tci.count_at(leaf_oid::regclass, ts);
  END LOOP;
  RETURN total;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered_partitioned(
  parent_table regclass,
  as_of timestamptz,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  total bigint := 0;
  missing text := '';
  typid oid;
  canon text;
  is_null boolean;
BEGIN
  PERFORM tci_internal.require_select(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);
  PERFORM tci_internal.require_rls_ok(parent_table);

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    SELECT * FROM tci_internal.resolve_filter_value(
      leaf_oid::regclass, filter_column, filter_value)
      INTO typid, canon, is_null;
    IF NOT EXISTS (
      SELECT 1 FROM tci_internal.indexes i
       WHERE i.source_oid = leaf_oid
         AND i.filter_col = filter_column
         AND i.filter_is_null = is_null
         AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
         AND i.published
    ) THEN
      missing := missing || format('%s ', leaf_oid::regclass);
    END IF;
  END LOOP;
  IF missing <> '' THEN
    RAISE EXCEPTION
      'pg_tci: missing filtered TCI (% = %) on leaf(s): %— run tci.create_filtered_partitioned',
      filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END,
      missing;
  END IF;

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    total := total + tci.count_at_filtered(
      leaf_oid::regclass, as_of, filter_column, filter_value);
  END LOOP;
  RETURN total;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.count_at_partitioned(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered_partitioned(regclass, timestamptz, name, text) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- maintain_partitioned / maintain_filters_partitioned
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.maintain_partitioned(
  parent_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8,
  budget_ms int DEFAULT 2000,
  max_active_writers int DEFAULT 4,
  max_seal_rows int DEFAULT 8192,
  do_compact boolean DEFAULT true,
  compact_mode text DEFAULT 'pairwise'
) RETURNS TABLE (
  leaf regclass,
  sealed boolean,
  compacted boolean,
  skipped_reason text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  r record;
BEGIN
  PERFORM tci_internal.require_admin(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    IF NOT EXISTS (
      SELECT 1 FROM tci_internal.indexes i
       WHERE i.source_oid = leaf_oid AND i.filter_col IS NULL
    ) THEN
      leaf := leaf_oid::regclass;
      sealed := false; compacted := false;
      skipped_reason := 'no_unfiltered_index';
      RETURN NEXT;
      CONTINUE;
    END IF;
    SELECT * INTO r FROM tci.maintain(
      leaf_oid::regclass, tail_target, max_live_runs, budget_ms,
      max_active_writers, max_seal_rows, do_compact, compact_mode);
    leaf := leaf_oid::regclass;
    sealed := r.sealed;
    compacted := r.compacted;
    skipped_reason := r.skipped_reason;
    RETURN NEXT;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION tci.maintain_filters_partitioned(
  parent_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8
) RETURNS TABLE (
  leaf regclass,
  index_id int,
  filter_col name,
  filter_value text,
  sealed bigint,
  compacted bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  leaf_oid oid;
  r record;
BEGIN
  PERFORM tci_internal.require_admin(parent_table);
  PERFORM tci_internal.require_partitioned_parent(parent_table);

  FOR leaf_oid IN SELECT * FROM tci_internal.partition_leaf_oids(parent_table) LOOP
    FOR r IN
      SELECT * FROM tci.maintain_filters(
        leaf_oid::regclass, tail_target, max_live_runs)
    LOOP
      leaf := leaf_oid::regclass;
      index_id := r.index_id;
      filter_col := r.filter_col;
      filter_value := r.filter_value;
      sealed := r.sealed;
      compacted := r.compacted;
      RETURN NEXT;
    END LOOP;
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION tci.maintain_partitioned(regclass, int, int, int, int, int, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maintain_filters_partitioned(regclass, int, int) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- count_at_safe / count_at_filtered_safe
-- ---------------------------------------------------------------------------
-- SET ROLE is forbidden inside SECURITY DEFINER. Catalog access stays DEFINER;
-- the actual heap COUNT runs as SECURITY INVOKER so session RLS applies.
CREATE OR REPLACE FUNCTION tci.safe_unfiltered_plan(source_table regclass)
RETURNS TABLE (use_native boolean, start_col name, end_col name)
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  start_c name;
  end_c name;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  IF NOT tci_internal.rls_blocks_packed(source_table) THEN
    RETURN QUERY SELECT false, NULL::name, NULL::name;
    RETURN;
  END IF;
  SELECT u.start_col, u.end_col INTO start_c, end_c
    FROM tci_internal.unfiltered_time_cols(source_table) u;
  IF start_c IS NULL THEN
    start_c := 'started_at';
    end_c := 'ended_at';
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute a
       WHERE a.attrelid = source_table AND a.attname = start_c AND NOT a.attisdropped
    ) THEN
      RAISE EXCEPTION
        'pg_tci: count_at_safe under RLS needs an unfiltered TCI (for start/end cols) or columns started_at/ended_at on %',
        source_table;
    END IF;
  END IF;
  RETURN QUERY SELECT true, start_c, end_c;
END;
$$;

CREATE OR REPLACE FUNCTION tci.safe_filtered_plan(
  source_table regclass,
  filter_column name,
  filter_value text
)
RETURNS TABLE (
  use_native boolean,
  start_col name,
  end_col name,
  filter_col name,
  filter_typid oid,
  filter_canon text,
  filter_is_null boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  IF NOT tci_internal.rls_blocks_packed(source_table) THEN
    RETURN QUERY SELECT false, NULL::name, NULL::name, NULL::name, NULL::oid, NULL::text, NULL::boolean;
    RETURN;
  END IF;
  BEGIN
    idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION
      'pg_tci: count_at_filtered_safe under RLS requires a registered filtered index on % (%=%)',
      source_table, filter_column, filter_value;
  END;
  RETURN QUERY SELECT true, idx.start_col, idx.end_col, idx.filter_col,
                      idx.filter_typid, idx.filter_value, idx.filter_is_null;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_safe(
  source_table regclass,
  ts timestamptz
) RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, tci, pg_temp
AS $$
DECLARE
  use_nat boolean;
  start_c name;
  end_c name;
  v bigint;
BEGIN
  SELECT p.use_native, p.start_col, p.end_col
    INTO use_nat, start_c, end_c
    FROM tci.safe_unfiltered_plan(source_table) p;
  IF NOT use_nat THEN
    RETURN tci.count_at(source_table, ts);
  END IF;
  EXECUTE format(
    'SELECT count(*)::bigint FROM %s s WHERE s.%I <= $1 AND (s.%I IS NULL OR s.%I > $1)',
    source_table, start_c, end_c, end_c)
    INTO v USING ts;
  RETURN v;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered_safe(
  source_table regclass,
  as_of timestamptz,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, tci, pg_temp
AS $$
DECLARE
  use_nat boolean;
  start_c name;
  end_c name;
  f_col name;
  f_typid oid;
  f_canon text;
  f_null boolean;
  v bigint;
  q text;
BEGIN
  SELECT p.use_native, p.start_col, p.end_col, p.filter_col, p.filter_typid,
         p.filter_canon, p.filter_is_null
    INTO use_nat, start_c, end_c, f_col, f_typid, f_canon, f_null
    FROM tci.safe_filtered_plan(source_table, filter_column, filter_value) p;
  IF NOT use_nat THEN
    RETURN tci.count_at_filtered(source_table, as_of, filter_column, filter_value);
  END IF;
  IF f_null THEN
    q := format(
      'SELECT count(*)::bigint FROM %s s WHERE s.%I IS NULL AND s.%I <= $1 AND (s.%I IS NULL OR s.%I > $1)',
      source_table, f_col, start_c, end_c, end_c);
    EXECUTE q INTO v USING as_of;
  ELSE
    q := format(
      'SELECT count(*)::bigint FROM %s s WHERE s.%I IS NOT DISTINCT FROM ($2::text)::%s AND s.%I <= $1 AND (s.%I IS NULL OR s.%I > $1)',
      source_table, f_col, format_type(f_typid, NULL), start_c, end_c, end_c);
    EXECUTE q INTO v USING as_of, f_canon;
  END IF;
  RETURN v;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.safe_unfiltered_plan(regclass) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.safe_filtered_plan(regclass, name, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_safe(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered_safe(regclass, timestamptz, name, text) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- admin_procedures: partitioned maintain
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
      'maint_history',
      'rebuild_filtered', 'drop_filtered', 'invalidate_filtered',
      'seal_filtered', 'compact_filtered', 'maintain_filters',
      'rebuild_invalid',
      'maintain_partitioned', 'maintain_filters_partitioned'
    ]);
$$;

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

COMMENT ON FUNCTION tci.create_partitioned(regclass, name, name, int, int, name, int) IS
  'Create unfiltered TCI on each heap leaf of a partitioned parent.';
COMMENT ON FUNCTION tci.count_at_partitioned(regclass, timestamptz) IS
  'Sum leaf tci.count_at; ERROR if any leaf lacks unfiltered index.';
COMMENT ON FUNCTION tci.count_at_safe(regclass, timestamptz) IS
  'Packed count when RLS allows; else native coverage under caller policies.';
COMMENT ON FUNCTION tci.count_at_filtered_safe(regclass, timestamptz, name, text) IS
  'Packed filtered count when RLS allows; else native filtered coverage.';
COMMENT ON SCHEMA tci IS
  'pg_tci public API (0.1.12 — partition fan-out + count_*_safe)';
