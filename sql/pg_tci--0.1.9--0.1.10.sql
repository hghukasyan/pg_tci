-- pg_tci 0.1.9 → 0.1.10
-- Pilot-ops hardening: rebuild_invalid helpers, maintain_filters relink,
-- filter_fit_estimate, richer health.detail. Bgworker multi-DB is C-only
-- (shared_preload GUCs; no SQL change required for worker).

-- ---------------------------------------------------------------------------
-- list_invalid / rebuild_invalid
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.list_invalid(
  source_table regclass DEFAULT NULL
)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  filter_col name,
  filter_value text,
  filter_is_null boolean,
  published boolean,
  valid boolean,
  notes text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  IF source_table IS NOT NULL THEN
    PERFORM tci_internal.require_select(source_table);
  END IF;

  RETURN QUERY
  SELECT i.index_id,
         format('%I.%I', i.source_nsp, i.source_rel)::text,
         i.filter_col,
         i.filter_value,
         i.filter_is_null,
         i.published,
         i.valid,
         i.notes
    FROM tci_internal.indexes i
   WHERE (NOT i.valid OR NOT i.published)
     AND (
       source_table IS NULL
       OR i.source_oid = source_table
       OR (i.source_nsp, i.source_rel) = (
            SELECT c.relnamespace::regnamespace::name, c.relname
              FROM pg_class c WHERE c.oid = source_table)
     )
   ORDER BY i.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.rebuild_invalid(
  source_table regclass DEFAULT NULL
)
RETURNS TABLE (
  index_id int,
  source_table_name text,
  filter_col name,
  filter_value text,
  action text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  r record;
  src regclass;
BEGIN
  FOR r IN
    SELECT i.index_id, i.source_nsp, i.source_rel, i.source_oid,
           i.filter_col, i.filter_value, i.filter_is_null
      FROM tci_internal.indexes i
     WHERE (NOT i.valid OR NOT i.published)
       AND (
         source_table IS NULL
         OR i.source_oid = source_table
         OR (i.source_nsp, i.source_rel) = (
              SELECT c.relnamespace::regnamespace::name, c.relname
                FROM pg_class c WHERE c.oid = source_table)
       )
     ORDER BY i.index_id
  LOOP
    BEGIN
      src := format('%I.%I', r.source_nsp, r.source_rel)::regclass;
    EXCEPTION WHEN OTHERS THEN
      index_id := r.index_id;
      source_table_name := format('%I.%I', r.source_nsp, r.source_rel);
      filter_col := r.filter_col;
      filter_value := r.filter_value;
      action := 'skip_missing_relation';
      RETURN NEXT;
      CONTINUE;
    END;

    PERFORM tci_internal.require_admin(src);

    IF r.filter_col IS NULL THEN
      PERFORM tci.rebuild(src);
      action := 'rebuild';
    ELSE
      PERFORM tci.rebuild_filtered(
        src, r.filter_col,
        CASE WHEN r.filter_is_null THEN NULL ELSE r.filter_value END);
      action := 'rebuild_filtered';
    END IF;

    index_id := r.index_id;
    source_table_name := format('%I.%I', r.source_nsp, r.source_rel);
    filter_col := r.filter_col;
    filter_value := r.filter_value;
    RETURN NEXT;
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION tci.list_invalid(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.rebuild_invalid(regclass) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tci.list_invalid(regclass) TO PUBLIC;

-- rebuild_invalid is admin (same as rebuild)
-- grant via grant_admin_execute update below

-- ---------------------------------------------------------------------------
-- maintain_filters: relink before work (post-restore OID drift)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.maintain_filters(
  source_table regclass,
  tail_target int DEFAULT 16384,
  max_live_runs int DEFAULT 8
) RETURNS TABLE (
  index_id int,
  filter_col name,
  filter_value text,
  sealed bigint,
  compacted bigint,
  n_tail bigint,
  live_runs int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  n_tail_cur bigint;
  n_live int;
  s_rid bigint;
  c_rid bigint;
BEGIN
  PERFORM tci_internal.require_admin(source_table);

  -- Relink filtered catalog rows (OID/name) before sealing
  FOR idx IN
    SELECT i.* FROM tci_internal.indexes i
    WHERE i.filter_col IS NOT NULL
      AND (
        i.source_oid = source_table
        OR (i.source_nsp, i.source_rel) = (
             SELECT c.relnamespace::regnamespace::name, c.relname
               FROM pg_class c WHERE c.oid = source_table)
      )
    ORDER BY i.index_id
  LOOP
    PERFORM tci_internal.relink_filtered(
      source_table, idx.filter_col,
      CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END);
  END LOOP;

  FOR idx IN
    SELECT i.* FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col IS NOT NULL
      AND i.published AND i.valid
    ORDER BY i.index_id
  LOOP
    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    s_rid := NULL;
    c_rid := NULL;
    IF n_tail_cur >= tail_target THEN
      s_rid := tci.seal_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END,
        GREATEST(tail_target, 8192));
    END IF;
    IF n_live >= max_live_runs THEN
      c_rid := tci.compact_filtered(
        source_table, idx.filter_col,
        CASE WHEN idx.filter_is_null THEN NULL ELSE idx.filter_value END);
    END IF;

    SELECT count(*) INTO n_tail_cur
    FROM tci_internal.tail t
    WHERE t.index_id = idx.index_id AND t.generation = idx.generation;
    SELECT count(*)::int INTO n_live
    FROM tci_internal.runs r
    WHERE r.index_id = idx.index_id AND r.status = 'live';

    index_id := idx.index_id;
    filter_col := idx.filter_col;
    filter_value := idx.filter_value;
    sealed := s_rid;
    compacted := c_rid;
    n_tail := n_tail_cur;
    live_runs := n_live;
    RETURN NEXT;
  END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- filter_fit_estimate — cardinality advisor (not a latency guarantee)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.filter_fit_estimate(
  source_table regclass,
  filter_column name
)
RETURNS TABLE (
  filter_col name,
  n_distinct_estimate double precision,
  registered_filters int,
  hint text,
  detail text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  nsp name;
  rel name;
  att name;
  nd double precision;
  nreg int;
  h text;
  d text;
BEGIN
  PERFORM tci_internal.require_select(source_table);

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;

  att := filter_column;

  SELECT s.n_distinct INTO nd
  FROM pg_stats s
  WHERE s.schemaname = nsp
    AND s.tablename = rel
    AND s.attname = att;

  SELECT count(*)::int INTO nreg
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column;

  IF nd IS NULL THEN
    h := 'measure_required';
    d := 'no pg_stats row — ANALYZE then re-check; always microbench';
  ELSIF nd < 0 THEN
    -- negative n_distinct => -fraction of rows that are distinct
    IF abs(nd) <= 0.02 THEN
      h := 'likely_ok';
      d := format('n_distinct=%s (scaled); low relative cardinality', nd);
    ELSIF abs(nd) <= 0.08 THEN
      h := 'measure_required';
      d := format('n_distinct=%s (scaled); mid cardinality — measure vs native', nd);
    ELSE
      h := 'native_may_win';
      d := format('n_distinct=%s (scaled); high relative cardinality', nd);
    END IF;
  ELSE
    IF nd <= 32 THEN
      h := 'likely_ok';
      d := format('n_distinct=%s; typical filtered TCI sweet spot ≤16–32', nd);
    ELSIF nd <= 64 THEN
      h := 'measure_required';
      d := format('n_distinct=%s; measure vs native before registering many filters', nd);
    ELSE
      h := 'native_may_win';
      d := format('n_distinct=%s; at ≥64–256 selective keys native often wins', nd);
    END IF;
  END IF;

  IF nreg > 32 AND h = 'likely_ok' THEN
    h := 'measure_required';
    d := d || format('; already %s registered filters', nreg);
  END IF;

  filter_col := filter_column;
  n_distinct_estimate := nd;
  registered_filters := nreg;
  hint := h;
  detail := d;
  RETURN NEXT;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.filter_fit_estimate(regclass, name) TO PUBLIC;

-- ---------------------------------------------------------------------------
-- Richer health.detail (write-amp / ops hints)
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
      WHEN NOT i.valid OR NOT i.published THEN
        'invalid_or_unpublished — count uses native fallback; run tci.rebuild / rebuild_invalid'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
           AND EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)) > 60
           AND (c.deltas_sealed / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1))
               < (c.deltas_ingested / GREATEST(EXTRACT(EPOCH FROM (clock_timestamp() - c.reset_at)), 1)) * 0.5
        THEN 'capacity_lag — seal slower than ingest; raise maint frequency/budget or reduce writers'::text
      WHEN (SELECT count(*) FROM tci_internal.tail t
             WHERE t.index_id = i.index_id AND t.generation = i.generation) > 65536
        THEN 'tail_large — run tci.maintain / maintain_filters; expect count latency growth'::text
      WHEN (SELECT count(*)::int FROM tci_internal.runs r
             WHERE r.index_id = i.index_id AND r.status = 'live') > 16
        THEN 'live_runs_high — compact; each live run adds decode cost'::text
      WHEN i.filter_col IS NOT NULL THEN
        format('filtered ok (col=%s); vacuum tci_internal.tail/chunks under write load', i.filter_col)::text
      ELSE 'ok — monitor n_tail vs seal rate; vacuum tci_internal under sustained writes'::text
    END
  FROM tci_internal.indexes i
  JOIN tci_internal.cap_counters c ON c.index_id = i.index_id
  WHERE i.index_id = idx.index_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- admin_procedures: include rebuild_invalid
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
      'rebuild_invalid'
    ]);
$$;

REVOKE ALL ON FUNCTION tci.rebuild_invalid(regclass) FROM PUBLIC;

-- Re-grant to current table owners
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

COMMENT ON FUNCTION tci.list_invalid(regclass) IS
  'List unpublished or invalid TCI indexes (optional source filter).';
COMMENT ON FUNCTION tci.rebuild_invalid(regclass) IS
  'Rebuild all invalid/unpublished indexes (unfiltered + filtered); admin.';
COMMENT ON FUNCTION tci.filter_fit_estimate(regclass, name) IS
  'Cardinality hint for filtered TCI vs native (not a latency guarantee).';
COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.10 — pilot-ops hardening)';
