-- pg_tci 0.1.8 → 0.1.9
-- Native filtered temporal coverage: partial TCI instances per equality filter.
-- Does NOT change TCIP v1, Packed IAR layout, or unfiltered count_at semantics.
-- No slice tables; deltas captured from the source table trigger.

-- ---------------------------------------------------------------------------
-- Catalog: allow multiple indexes per source (one unfiltered + N filtered)
-- ---------------------------------------------------------------------------
ALTER TABLE tci_internal.indexes
  DROP CONSTRAINT IF EXISTS indexes_source_oid_key;

ALTER TABLE tci_internal.indexes
  ADD COLUMN IF NOT EXISTS filter_col name,
  ADD COLUMN IF NOT EXISTS filter_value text,
  ADD COLUMN IF NOT EXISTS filter_typid oid,
  ADD COLUMN IF NOT EXISTS filter_is_null boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN tci_internal.indexes.filter_col IS
  'NULL = unfiltered index; else single-column equality filter column';
COMMENT ON COLUMN tci_internal.indexes.filter_value IS
  'Canonical text of equality value (cast via filter_typid); unused when filter_is_null';
COMMENT ON COLUMN tci_internal.indexes.filter_is_null IS
  'When true, this filtered index matches rows where filter_col IS NULL';

-- Exactly one unfiltered index per source OID
CREATE UNIQUE INDEX IF NOT EXISTS indexes_unfiltered_source_uidx
  ON tci_internal.indexes (source_oid)
  WHERE filter_col IS NULL;

-- Exactly one filtered index per (source, column, value|NULL)
CREATE UNIQUE INDEX IF NOT EXISTS indexes_filtered_source_uidx
  ON tci_internal.indexes (
    source_oid,
    filter_col,
    filter_is_null,
    COALESCE(filter_value, '')
  )
  WHERE filter_col IS NOT NULL;

CREATE INDEX IF NOT EXISTS indexes_filter_lookup_idx
  ON tci_internal.indexes (source_oid, filter_col, filter_is_null, filter_value)
  WHERE filter_col IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Type-safe filter value resolution (no dynamic SQL injection of values)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.supported_filter_type(typid oid)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT typid IN (
    'text'::regtype::oid,
    'varchar'::regtype::oid,
    'bpchar'::regtype::oid,
    'int4'::regtype::oid,
    'int8'::regtype::oid,
    'int2'::regtype::oid
  )
  OR EXISTS (
    SELECT 1 FROM pg_type t
    WHERE t.oid = typid AND t.typtype = 'e'
  );
$$;

-- Resolve user-supplied text to (typid, canonical text, is_null).
-- p_filter_value NULL => match IS NULL (filter_is_null=true).
CREATE OR REPLACE FUNCTION tci_internal.resolve_filter_value(
  p_source regclass,
  p_filter_col name,
  p_filter_value text,
  OUT o_typid oid,
  OUT o_canon text,
  OUT o_is_null boolean
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  att_ty oid;
  typname text;
  q text;
BEGIN
  SELECT a.atttypid INTO att_ty
  FROM pg_attribute a
  WHERE a.attrelid = p_source
    AND a.attname = p_filter_col
    AND NOT a.attisdropped
    AND a.attnum > 0;
  IF att_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: filter column % not found on %',
      p_filter_col, p_source;
  END IF;
  IF NOT tci_internal.supported_filter_type(att_ty) THEN
    RAISE EXCEPTION
      'pg_tci: filter column % type % not supported (text/varchar/int/bigint/enum)',
      p_filter_col, att_ty::regtype;
  END IF;

  o_typid := att_ty;
  IF p_filter_value IS NULL THEN
    o_canon := NULL;
    o_is_null := true;
    RETURN;
  END IF;

  o_is_null := false;
  typname := format_type(att_ty, NULL);
  -- Bind as text, cast to real column type, emit canonical text.
  -- Uses typed parameter — never interpolates the value into SQL text.
  q := format('SELECT ($1::text)::%s::text', typname);
  BEGIN
    EXECUTE q INTO o_canon USING p_filter_value;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION
      'pg_tci: filter_value % is not a valid literal for type %',
      p_filter_value, att_ty::regtype
      USING ERRCODE = '22P02';
  END;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.native_count_filtered(
  p_source regclass,
  p_start name,
  p_end name,
  p_filter_col name,
  p_typid oid,
  p_canon text,
  p_is_null boolean,
  p_ts timestamptz
) RETURNS bigint
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v bigint;
  q text;
  typname text := format_type(p_typid, NULL);
BEGIN
  IF p_is_null THEN
    q := format(
      'SELECT count(*)::bigint FROM %s s
        WHERE s.%I IS NULL
          AND s.%I <= $1
          AND (s.%I IS NULL OR s.%I > $1)',
      p_source, p_filter_col, p_start, p_end, p_end);
    EXECUTE q INTO v USING p_ts;
  ELSE
    q := format(
      'SELECT count(*)::bigint FROM %s s
        WHERE s.%I IS NOT DISTINCT FROM ($2::text)::%s
          AND s.%I <= $1
          AND (s.%I IS NULL OR s.%I > $1)',
      p_source, p_filter_col, typname, p_start, p_end, p_end);
    EXECUTE q INTO v USING p_ts, p_canon;
  END IF;
  RETURN v;
END;
$$;

-- Row filter value as canonical text (NULL => SQL NULL)
CREATE OR REPLACE FUNCTION tci_internal.row_filter_canon(
  p_row record,
  p_filter_col name,
  p_typid oid
) RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  typname text := format_type(p_typid, NULL);
  v text;
BEGIN
  EXECUTE format('SELECT (($1).%I)::%s::text', p_filter_col, typname)
    INTO v USING p_row;
  RETURN v;
END;
$$;

-- ---------------------------------------------------------------------------
-- Lookups: unfiltered vs filtered (never confuse the two)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.relink_source(source_table regclass)
RETURNS tci_internal.indexes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  nsp name;
  rel name;
  new_oid oid;
  start_ty oid;
  end_ty oid;
  conflict int;
BEGIN
  -- Prefer exact OID match on the UNFILTERED index only
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = source_table
    AND filter_col IS NULL;
  IF FOUND THEN
    SELECT c.relnamespace::regnamespace::name, c.relname
      INTO nsp, rel
    FROM pg_class c WHERE c.oid = source_table;
    IF nsp IS DISTINCT FROM idx.source_nsp OR rel IS DISTINCT FROM idx.source_rel THEN
      UPDATE tci_internal.indexes
         SET valid = false, published = false,
             notes = coalesce(notes,'') || format(' [oid/name mismatch %s]', clock_timestamp())
       WHERE index_id = idx.index_id
       RETURNING * INTO idx;
      RAISE EXCEPTION
        'pg_tci: source_oid % no longer matches cataloged % . % — fail closed (rebuild/create)',
        source_table, idx.source_nsp, idx.source_rel;
    END IF;

    SELECT a.atttypid INTO start_ty FROM pg_attribute a
     WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
    SELECT a.atttypid INTO end_ty FROM pg_attribute a
     WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
    IF start_ty IS NULL OR end_ty IS NULL
       OR start_ty <> 'timestamptz'::regtype
       OR end_ty <> 'timestamptz'::regtype THEN
      UPDATE tci_internal.indexes
         SET valid = false, published = false,
             notes = coalesce(notes,'') || format(' [column type/missing %s]', clock_timestamp())
       WHERE index_id = idx.index_id;
      RAISE EXCEPTION
        'pg_tci: indexed columns on % missing or not timestamptz — fail closed',
        source_table;
    END IF;
    RETURN idx;
  END IF;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_nsp = nsp AND source_rel = rel
    AND filter_col IS NULL
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: no index for % — call tci.create first', source_table;
  END IF;

  SELECT count(*) INTO conflict
  FROM tci_internal.indexes i
  WHERE i.index_id <> idx.index_id
    AND i.source_oid = source_table
    AND i.filter_col IS NULL;
  IF conflict > 0 THEN
    RAISE EXCEPTION
      'pg_tci: refusing relink — OID % already bound to another unfiltered index',
      source_table;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL
     OR start_ty <> 'timestamptz'::regtype
     OR end_ty <> 'timestamptz'::regtype THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [relink refused bad cols %s]', clock_timestamp())
     WHERE index_id = idx.index_id;
    RAISE EXCEPTION
      'pg_tci: cannot relink % — columns % / % not timestamptz',
      source_table, idx.start_col, idx.end_col;
  END IF;

  new_oid := source_table;
  UPDATE tci_internal.indexes
     SET source_oid = new_oid,
         valid = false,
         published = false,
         notes = coalesce(notes, '') || format(
           ' [relink oid %s — invalidated pending rebuild]', clock_timestamp())
   WHERE index_id = idx.index_id
   RETURNING * INTO idx;

  -- Also rebind filtered indexes that share the same nsp/rel name
  UPDATE tci_internal.indexes
     SET source_oid = new_oid,
         valid = false,
         published = false,
         notes = coalesce(notes, '') || format(
           ' [relink oid %s — invalidated pending rebuild]', clock_timestamp())
   WHERE source_nsp = nsp AND source_rel = rel
     AND filter_col IS NOT NULL
     AND source_oid IS DISTINCT FROM new_oid;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = new_oid AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      new_oid::regclass);
  END IF;

  RETURN idx;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.relink_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS tci_internal.indexes
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  typid oid;
  canon text;
  is_null boolean;
  nsp name;
  rel name;
  start_ty oid;
  end_ty oid;
  fty oid;
BEGIN
  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT c.relnamespace::regnamespace::name, c.relname
    INTO nsp, rel
  FROM pg_class c WHERE c.oid = source_table;
  IF nsp IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', source_table;
  END IF;

  -- Prefer OID match
  SELECT * INTO idx
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column
    AND i.filter_is_null = is_null
    AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon);

  -- Dump/restore: OID changed under same nsp/rel — rebind all matching filters
  IF NOT FOUND THEN
    SELECT * INTO idx
    FROM tci_internal.indexes i
    WHERE i.source_nsp = nsp AND i.source_rel = rel
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION
        'pg_tci: no filtered index for %(%=%) — call tci.create_filtered first',
        source_table, filter_column,
        CASE WHEN is_null THEN 'NULL' ELSE canon END;
    END IF;
    UPDATE tci_internal.indexes
       SET source_oid = source_table,
           valid = false,
           published = false,
           notes = coalesce(notes, '') || format(
             ' [relink oid %s — invalidated pending rebuild_filtered]', clock_timestamp())
     WHERE source_nsp = nsp AND source_rel = rel
       AND filter_col IS NOT NULL
       AND source_oid IS DISTINCT FROM source_table;
    SELECT * INTO idx FROM tci_internal.indexes WHERE index_id = idx.index_id;
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger
      WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
    ) THEN
      EXECUTE format(
        'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
         FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
        source_table);
    END IF;
    RETURN idx;  -- invalid until rebuild_filtered (fail closed, no stale packed)
  END IF;

  IF nsp IS DISTINCT FROM idx.source_nsp OR rel IS DISTINCT FROM idx.source_rel THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [oid/name mismatch %s]', clock_timestamp())
     WHERE index_id = idx.index_id
     RETURNING * INTO idx;
    RAISE EXCEPTION
      'pg_tci: filtered source_oid % no longer matches cataloged % . %',
      source_table, idx.source_nsp, idx.source_rel;
  END IF;

  SELECT a.atttypid INTO start_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.start_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.end_col AND NOT a.attisdropped;
  SELECT a.atttypid INTO fty FROM pg_attribute a
   WHERE a.attrelid = source_table AND a.attname = idx.filter_col AND NOT a.attisdropped;

  IF start_ty IS NULL OR end_ty IS NULL OR fty IS NULL
     OR start_ty <> 'timestamptz'::regtype
     OR end_ty <> 'timestamptz'::regtype
     OR fty IS DISTINCT FROM idx.filter_typid THEN
    UPDATE tci_internal.indexes
       SET valid = false, published = false,
           notes = coalesce(notes,'') || format(' [filter col type/missing %s]', clock_timestamp())
     WHERE index_id = idx.index_id;
    RAISE EXCEPTION
      'pg_tci: filtered index columns on % missing or type-changed — fail closed',
      source_table;
  END IF;

  RETURN idx;
END;
$$;

-- ---------------------------------------------------------------------------
-- event_rows: honor filter predicate for rebuild of filtered indexes
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.event_rows(p_index_id int)
RETURNS TABLE(ts timestamptz, delta smallint)
LANGUAGE plpgsql
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  q text;
  typname text;
BEGIN
  SELECT * INTO STRICT idx FROM tci_internal.indexes WHERE index_id = p_index_id;

  IF idx.filter_col IS NULL THEN
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s WHERE s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.end_col);
    RETURN QUERY EXECUTE q;
  ELSIF idx.filter_is_null THEN
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s WHERE s.%I IS NULL
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s
         WHERE s.%I IS NULL AND s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel, idx.filter_col,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.filter_col, idx.end_col);
    RETURN QUERY EXECUTE q;
  ELSE
    typname := format_type(idx.filter_typid, NULL);
    q := format(
      $f$
        SELECT s.%I, 1::smallint FROM %I.%I s
         WHERE s.%I IS NOT DISTINCT FROM ($1::text)::%s
        UNION ALL
        SELECT s.%I, (-1)::smallint FROM %I.%I s
         WHERE s.%I IS NOT DISTINCT FROM ($1::text)::%s
           AND s.%I IS NOT NULL
      $f$,
      idx.start_col, idx.source_nsp, idx.source_rel, idx.filter_col, typname,
      idx.end_col, idx.source_nsp, idx.source_rel, idx.filter_col, typname,
      idx.end_col);
    RETURN QUERY EXECUTE q USING idx.filter_value;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Tail helpers for trigger (interval ±1 on one index)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.tail_add_interval(
  p_idx tci_internal.indexes,
  p_id bigint,
  p_start timestamptz,
  p_end timestamptz,
  p_sign smallint   -- +1 contribute, -1 remove
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  sid int;
BEGIN
  IF NOT p_idx.published OR NOT p_idx.valid THEN
    RETURN;
  END IF;
  IF p_idx.shard_count > 1 AND p_id IS NULL THEN
    RAISE EXCEPTION 'pg_tci: NULL % not allowed for sharded index', p_idx.id_col;
  END IF;
  sid := tci_internal.row_shard_v1(p_idx.shard_count, p_id);
  INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
  VALUES (p_idx.index_id, p_idx.generation, sid, p_start, p_sign);
  IF p_end IS NOT NULL THEN
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_end, (-p_sign)::smallint);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci_internal.tail_adjust_bounds(
  p_idx tci_internal.indexes,
  p_id bigint,
  p_start_old timestamptz,
  p_end_old timestamptz,
  p_start_new timestamptz,
  p_end_new timestamptz
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  sid int;
BEGIN
  IF NOT p_idx.published OR NOT p_idx.valid THEN
    RETURN;
  END IF;
  IF p_start_old IS NOT DISTINCT FROM p_start_new
     AND p_end_old IS NOT DISTINCT FROM p_end_new THEN
    RETURN;
  END IF;
  sid := tci_internal.row_shard_v1(p_idx.shard_count, p_id);

  IF p_start_old IS DISTINCT FROM p_start_new THEN
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_start_old, -1);
    INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
    VALUES (p_idx.index_id, p_idx.generation, sid, p_start_new, 1);
  END IF;

  IF p_end_old IS DISTINCT FROM p_end_new THEN
    IF p_end_old IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (p_idx.index_id, p_idx.generation, sid, p_end_old, 1);
    END IF;
    IF p_end_new IS NOT NULL THEN
      INSERT INTO tci_internal.tail(index_id, generation, shard_id, ts, delta)
      VALUES (p_idx.index_id, p_idx.generation, sid, p_end_new, -1);
    END IF;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Trigger: unfiltered + filtered routing (cost ~ #distinct filter columns)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci_internal.source_trig()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  start_old timestamptz;
  end_old timestamptz;
  start_new timestamptz;
  end_new timestamptz;
  id_old bigint;
  id_new bigint;
  fcol name;
  canon_old text;
  canon_new text;
  null_old boolean;
  null_new boolean;
  has_filtered boolean;
BEGIN
  -- ---- Unfiltered index (0 or 1) ----
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID
    AND filter_col IS NULL
  FOR KEY SHARE;

  IF FOUND AND idx.published AND idx.valid THEN
    IF TG_OP = 'INSERT' THEN
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_new, start_new, end_new USING NEW;
      PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
    ELSIF TG_OP = 'DELETE' THEN
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_old, start_old, end_old USING OLD;
      PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
    ELSIF TG_OP = 'UPDATE' THEN
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_old, start_old, end_old USING OLD;
      EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                     idx.id_col, idx.start_col, idx.end_col)
        INTO id_new, start_new, end_new USING NEW;
      IF id_old IS DISTINCT FROM id_new THEN
        RAISE EXCEPTION 'pg_tci: primary key % change not supported (%/%)',
          idx.id_col, id_old, id_new;
      END IF;
      PERFORM tci_internal.tail_adjust_bounds(
        idx, id_old, start_old, end_old, start_new, end_new);
    END IF;
  END IF;

  -- ---- Filtered indexes ----
  SELECT EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = TG_RELID AND filter_col IS NOT NULL
  ) INTO has_filtered;

  IF NOT has_filtered THEN
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;

  -- Use id/start/end from first filtered catalog row (same source columns).
  SELECT * INTO idx
  FROM tci_internal.indexes
  WHERE source_oid = TG_RELID AND filter_col IS NOT NULL
  LIMIT 1;

  IF TG_OP = 'INSERT' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
  ELSIF TG_OP = 'DELETE' THEN
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
  ELSE
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_old, start_old, end_old USING OLD;
    EXECUTE format('SELECT ($1).%I::bigint, ($1).%I, ($1).%I',
                   idx.id_col, idx.start_col, idx.end_col)
      INTO id_new, start_new, end_new USING NEW;
    IF id_old IS DISTINCT FROM id_new THEN
      RAISE EXCEPTION 'pg_tci: primary key % change not supported (%/%)',
        idx.id_col, id_old, id_new;
    END IF;
  END IF;

  FOR fcol IN
    SELECT DISTINCT i.filter_col
    FROM tci_internal.indexes i
    WHERE i.source_oid = TG_RELID
      AND i.filter_col IS NOT NULL
  LOOP
    -- Resolve OLD/NEW filter canons for this column (type from any matching index)
    SELECT i.filter_typid INTO idx.filter_typid
    FROM tci_internal.indexes i
    WHERE i.source_oid = TG_RELID AND i.filter_col = fcol
    LIMIT 1;

    IF TG_OP = 'INSERT' THEN
      canon_new := tci_internal.row_filter_canon(NEW, fcol, idx.filter_typid);
      null_new := (canon_new IS NULL);
      FOR idx IN
        SELECT * FROM tci_internal.indexes i
        WHERE i.source_oid = TG_RELID
          AND i.filter_col = fcol
          AND i.filter_is_null = null_new
          AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
        FOR KEY SHARE
      LOOP
        PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
      END LOOP;

    ELSIF TG_OP = 'DELETE' THEN
      canon_old := tci_internal.row_filter_canon(OLD, fcol, idx.filter_typid);
      null_old := (canon_old IS NULL);
      FOR idx IN
        SELECT * FROM tci_internal.indexes i
        WHERE i.source_oid = TG_RELID
          AND i.filter_col = fcol
          AND i.filter_is_null = null_old
          AND (null_old OR i.filter_value IS NOT DISTINCT FROM canon_old)
        FOR KEY SHARE
      LOOP
        PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
      END LOOP;

    ELSIF TG_OP = 'UPDATE' THEN
      canon_old := tci_internal.row_filter_canon(OLD, fcol, idx.filter_typid);
      canon_new := tci_internal.row_filter_canon(NEW, fcol, idx.filter_typid);
      null_old := (canon_old IS NULL);
      null_new := (canon_new IS NULL);

      IF null_old IS DISTINCT FROM null_new
         OR canon_old IS DISTINCT FROM canon_new THEN
        -- Filter value moved: remove from old bucket, add to new
        FOR idx IN
          SELECT * FROM tci_internal.indexes i
          WHERE i.source_oid = TG_RELID
            AND i.filter_col = fcol
            AND i.filter_is_null = null_old
            AND (null_old OR i.filter_value IS NOT DISTINCT FROM canon_old)
          FOR KEY SHARE
        LOOP
          PERFORM tci_internal.tail_add_interval(idx, id_old, start_old, end_old, (-1)::smallint);
        END LOOP;
        FOR idx IN
          SELECT * FROM tci_internal.indexes i
          WHERE i.source_oid = TG_RELID
            AND i.filter_col = fcol
            AND i.filter_is_null = null_new
            AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
          FOR KEY SHARE
        LOOP
          PERFORM tci_internal.tail_add_interval(idx, id_new, start_new, end_new, 1::smallint);
        END LOOP;
      ELSE
        -- Same filter bucket: only adjust if interval bounds changed
        IF start_old IS DISTINCT FROM start_new
           OR end_old IS DISTINCT FROM end_new THEN
          FOR idx IN
            SELECT * FROM tci_internal.indexes i
            WHERE i.source_oid = TG_RELID
              AND i.filter_col = fcol
              AND i.filter_is_null = null_new
              AND (null_new OR i.filter_value IS NOT DISTINCT FROM canon_new)
            FOR KEY SHARE
          LOOP
            PERFORM tci_internal.tail_adjust_bounds(
              idx, id_new, start_old, end_old, start_new, end_new);
          END LOOP;
        END IF;
      END IF;
    END IF;
  END LOOP;

  IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- create(): uniqueness is unfiltered-only
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

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = source_table AND filter_col IS NULL
  ) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_nsp = nsp AND source_rel = rel AND filter_col IS NULL
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

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild(source_table);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Public filtered API
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tci.create_filtered(
  source_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,
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
  typid oid;
  canon text;
  is_null boolean;
  -- inherit start/end from existing unfiltered if present
  base tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;
  IF chunk_bytes NOT IN (4096, 8192, 16384, 32768) THEN
    RAISE EXCEPTION 'pg_tci: chunk_bytes must be 4096|8192|16384|32768';
  END IF;
  IF cp_interval NOT IN (32, 64, 128) THEN
    RAISE EXCEPTION 'pg_tci: cp_interval must be 32|64|128';
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
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_column, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF filter_column IN (start_column, end_column, id_col) THEN
    RAISE EXCEPTION 'pg_tci: filter_column must be distinct from start/end/id columns';
  END IF;

  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  -- If an unfiltered index exists, require matching interval columns
  SELECT * INTO base
  FROM tci_internal.indexes
  WHERE source_oid = source_table AND filter_col IS NULL;
  IF FOUND THEN
    IF base.start_col IS DISTINCT FROM start_column
       OR base.end_col IS DISTINCT FROM end_column THEN
      RAISE EXCEPTION
        'pg_tci: filtered start/end must match existing unfiltered index (% / %)',
        base.start_col, base.end_col;
    END IF;
    IF base.id_col IS DISTINCT FROM id_col THEN
      RAISE EXCEPTION
        'pg_tci: filtered id_col must match existing unfiltered index (%)',
        base.id_col;
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
  ) THEN
    RAISE EXCEPTION 'pg_tci: filtered index already exists for %(%=%)',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid,
    filter_col, filter_value, filter_typid, filter_is_null)
  VALUES (
    source_table, nsp, rel, start_column, end_column,
    chunk_bytes, cp_interval, id_col, shard_count, false, true,
    filter_column, canon, typid, is_null)
  RETURNING index_id INTO idx_id;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered(
  source_table regclass,
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
  idx tci_internal.indexes%ROWTYPE;
  typid oid;
  canon text;
  is_null boolean;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT * INTO idx
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col = filter_column
    AND i.filter_is_null = is_null
    AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon);

  IF NOT FOUND THEN
    -- Never silently use another filter or the unfiltered index.
    RAISE EXCEPTION
      'pg_tci: no filtered index for %(%=%) — create_filtered or use native COUNT',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END
      USING ERRCODE = 'P0002';
  END IF;

  -- Identity / type sanity (fail closed)
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count_filtered(
      source_table, idx.start_col, idx.end_col,
      idx.filter_col, idx.filter_typid, idx.filter_value, idx.filter_is_null,
      as_of);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, as_of)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, as_of);
END;
$$;

CREATE OR REPLACE FUNCTION tci.rebuild_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;

  DELETE FROM tci_internal.chunks WHERE index_id = idx.index_id;
  DELETE FROM tci_internal.runs WHERE index_id = idx.index_id;
  DELETE FROM tci_internal.tail WHERE index_id = idx.index_id;

  UPDATE tci_internal.indexes
     SET generation = generation + 1,
         published = false,
         valid = true
   WHERE index_id = idx.index_id
   RETURNING * INTO idx;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn,
         ts,
         tci_internal.ts_us(ts) AS ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT e.ts, sum(e.delta)::bigint AS delta
    FROM tci_internal.event_rows(idx.index_id) e
    GROUP BY e.ts HAVING sum(e.delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;

  IF n > 0 THEN
    INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
    VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, 0)
    RETURNING run_id INTO rid;
    PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);
  END IF;

  UPDATE tci_internal.indexes
     SET published = true,
         valid = true,
         notes = coalesce(notes, '') || format(
           ' [rebuild_filtered %s n=%s]', clock_timestamp(), n)
   WHERE index_id = idx.index_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.drop_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  DELETE FROM tci_internal.indexes WHERE index_id = idx.index_id;

  -- Drop shared trigger only when no indexes remain for this source
  IF NOT EXISTS (
    SELECT 1 FROM tci_internal.indexes WHERE source_oid = source_table
  ) THEN
    EXECUTE format('DROP TRIGGER IF EXISTS tci_source_trig ON %s', source_table);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tci.invalidate_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.acquire_all_shard_locks(idx.index_id, idx.shard_count);
  PERFORM 1 FROM tci_internal.indexes WHERE index_id = idx.index_id FOR UPDATE;
  UPDATE tci_internal.indexes
     SET valid = false,
         published = false,
         notes = coalesce(notes, '') || format(' [invalidated_filtered %s]', clock_timestamp())
   WHERE index_id = idx.index_id;
END;
$$;

-- Seal one filtered index (batch-ID exact-once; safe under concurrent writers)
DROP FUNCTION IF EXISTS tci.seal_filtered(regclass, name, text);
CREATE OR REPLACE FUNCTION tci.seal_filtered(
  source_table regclass,
  filter_column name,
  filter_value text,
  max_rows int DEFAULT 8192
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
  rid bigint;
  n int;
  n_src bigint;
  got_lock boolean;
  batch_ids bigint[];
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF max_rows < 1 THEN
    RAISE EXCEPTION 'pg_tci: max_rows must be >= 1';
  END IF;

  got_lock := tci_internal.try_all_shard_locks(idx.index_id, idx.shard_count);
  IF NOT got_lock THEN
    RETURN NULL;
  END IF;
  IF NOT idx.valid OR NOT idx.published THEN
    RAISE EXCEPTION 'pg_tci: filtered index for % is not published/valid', source_table;
  END IF;

  IF to_regclass('pg_temp._tci_batch') IS NOT NULL THEN
    DROP TABLE _tci_batch;
  END IF;
  -- Lock a finite batch of tail row IDs so concurrent inserts are not deleted
  -- without being packed (same exact-once pattern as seal_bounded).
  CREATE TEMP TABLE _tci_batch ON COMMIT DROP AS
  SELECT t.id, t.ts, t.delta
  FROM tci_internal.tail t
  WHERE t.index_id = idx.index_id
    AND t.generation = idx.generation
  ORDER BY t.id
  LIMIT max_rows
  FOR UPDATE OF t SKIP LOCKED;

  SELECT count(*) INTO n_src FROM _tci_batch;
  IF n_src = 0 THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(id) INTO batch_ids FROM _tci_batch;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  SELECT row_number() OVER (ORDER BY ts) AS rn,
         ts,
         tci_internal.ts_us(ts) AS ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts)::bigint AS prefix_sum
  FROM (
    SELECT b.ts, sum(b.delta)::bigint AS delta
    FROM _tci_batch b
    GROUP BY b.ts HAVING sum(b.delta) <> 0
  ) s;

  SELECT count(*) INTO n FROM _tci_pref;
  IF n = 0 THEN
    DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (idx.index_id, 'live', n, idx.chunk_bytes, idx.cp_interval, 0)
  RETURNING run_id INTO rid;
  PERFORM tci_internal.insert_chunks(idx.index_id, rid, idx.chunk_bytes, idx.cp_interval);

  DELETE FROM tci_internal.tail WHERE id = ANY (batch_ids);

  RETURN rid;
END;
$$;

CREATE OR REPLACE FUNCTION tci.compact_filtered(
  source_table regclass,
  filter_column name,
  filter_value text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);
  -- Reuse pairwise compact via temporarily routing through source-only API
  -- is unsafe (would hit unfiltered). Inline minimal pairwise for this index_id.
  RETURN tci_internal.compact_pairwise_index(idx.index_id, idx.shard_count);
END;
$$;

-- Minimal pairwise compact by index_id (shared by filtered maintain)
CREATE OR REPLACE FUNCTION tci_internal.compact_pairwise_index(
  p_index_id int,
  p_shard_count int
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r1 record;
  r2 record;
  rid bigint;
  n int;
  got_lock boolean;
  cb int;
  cp int;
BEGIN
  got_lock := tci_internal.try_all_shard_locks(p_index_id, p_shard_count);
  IF NOT got_lock THEN
    RETURN NULL;
  END IF;

  SELECT run_id, n_entries INTO r1
  FROM tci_internal.runs
  WHERE index_id = p_index_id AND status = 'live'
  ORDER BY run_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT run_id, n_entries INTO r2
  FROM tci_internal.runs
  WHERE index_id = p_index_id AND status = 'live' AND run_id > r1.run_id
  ORDER BY run_id
  LIMIT 1;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  SELECT chunk_bytes, cp_interval INTO cb, cp
  FROM tci_internal.indexes WHERE index_id = p_index_id;

  IF to_regclass('pg_temp._tci_pref') IS NOT NULL THEN
    DROP TABLE _tci_pref;
  END IF;

  -- Merge two live runs: unpack → coalesce by ts_us → rebuild prefix table.
  -- Timestamps are µs since PostgreSQL epoch 2000-01-01 (TCIP v1).
  CREATE TEMP TABLE _tci_pref ON COMMIT DROP AS
  WITH entries AS (
    SELECT e.ts_us, e.delta::bigint AS delta
    FROM tci_internal.runs r
    JOIN tci_internal.chunks c ON c.index_id = r.index_id AND c.run_id = r.run_id
    CROSS JOIN LATERAL tci_internal.unpack_entries(c.payload) e
    WHERE r.index_id = p_index_id
      AND r.run_id IN (r1.run_id, r2.run_id)
      AND r.status = 'live'
  ),
  merged AS (
    SELECT ts_us, sum(delta)::bigint AS delta
    FROM entries
    GROUP BY ts_us
    HAVING sum(delta) <> 0
  )
  SELECT row_number() OVER (ORDER BY ts_us) AS rn,
         (TIMESTAMPTZ '2000-01-01 00:00:00+00'
            + (ts_us * INTERVAL '1 microsecond')) AS ts,
         ts_us,
         delta::smallint AS delta,
         sum(delta) OVER (ORDER BY ts_us)::bigint AS prefix_sum
  FROM merged;

  SELECT count(*) INTO n FROM _tci_pref;
  IF n = 0 THEN
    DELETE FROM tci_internal.chunks
     WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
    DELETE FROM tci_internal.runs
     WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
    RETURN NULL;
  END IF;

  INSERT INTO tci_internal.runs(index_id, status, n_entries, chunk_bytes, cp_interval, shard_id)
  VALUES (p_index_id, 'live', n, cb, cp, 0)
  RETURNING run_id INTO rid;

  PERFORM tci_internal.insert_chunks(p_index_id, rid, cb, cp);

  DELETE FROM tci_internal.chunks
   WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);
  DELETE FROM tci_internal.runs
   WHERE index_id = p_index_id AND run_id IN (r1.run_id, r2.run_id);

  RETURN rid;
END;
$$;

-- Round-robin maintain across all filtered indexes on a source table
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

CREATE OR REPLACE FUNCTION tci.list_filters(source_table regclass)
RETURNS TABLE (
  index_id int,
  filter_col name,
  filter_value text,
  filter_is_null boolean,
  published boolean,
  valid boolean,
  generation bigint,
  n_tail bigint,
  live_runs int
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
BEGIN
  PERFORM tci_internal.require_select(source_table);
  RETURN QUERY
  SELECT i.index_id, i.filter_col, i.filter_value, i.filter_is_null,
         i.published, i.valid, i.generation,
         (SELECT count(*) FROM tci_internal.tail t
           WHERE t.index_id = i.index_id AND t.generation = i.generation),
         (SELECT count(*)::int FROM tci_internal.runs r
           WHERE r.index_id = i.index_id AND r.status = 'live')
  FROM tci_internal.indexes i
  WHERE i.source_oid = source_table
    AND i.filter_col IS NOT NULL
  ORDER BY i.filter_col, i.filter_is_null, i.filter_value;
END;
$$;

-- ---------------------------------------------------------------------------
-- Privileges
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
      'seal_filtered', 'compact_filtered', 'maintain_filters'
    ]);
$$;

-- create_filtered stays PUBLIC for owner bootstrap (like tci.create)
GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.list_filters(regclass) TO PUBLIC;

REVOKE ALL ON FUNCTION tci.rebuild_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.drop_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.invalidate_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.seal_filtered(regclass, name, text, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.compact_filtered(regclass, name, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci.maintain_filters(regclass, int, int) FROM PUBLIC;

-- Re-grant admin EXECUTE to current table owners (includes new filtered admin APIs)
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

COMMENT ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) IS
  'Create a partial TCI for single-column equality filter (no row copies).';
COMMENT ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) IS
  'Exact filtered interval COUNT via registered partial TCI; errors if unregistered.';
COMMENT ON FUNCTION tci.maintain_filters(regclass, int, int) IS
  'Seal/compact all filtered TCI instances on a source table.';

COMMENT ON SCHEMA tci IS 'pg_tci public API (0.1.9 — native filtered coverage)';

-- grant_admin / revoke_admin: include create_filtered bootstrap grant
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
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create(regclass, name, name, int, int, name, int) TO %I',
    target_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO %I',
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
  EXECUTE format(
    'REVOKE ALL ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) FROM %I',
    target_role);
END;
$$;

-- ===========================================================================
-- 0.1.9 hardening: RLS fail-closed, reject partitions, storage accounting
-- ===========================================================================

CREATE OR REPLACE FUNCTION tci_internal.require_plain_heap(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  kind "char";
  ispart boolean;
BEGIN
  SELECT c.relkind, c.relispartition
    INTO kind, ispart
  FROM pg_class c WHERE c.oid = p_source;
  IF kind IS NULL THEN
    RAISE EXCEPTION 'pg_tci: source table % not found', p_source;
  END IF;
  IF kind = 'p' OR ispart THEN
    RAISE EXCEPTION
      'pg_tci: partitioned tables are not supported (source %)', p_source
      USING ERRCODE = '0A000';
  END IF;
  IF kind <> 'r' THEN
    RAISE EXCEPTION
      'pg_tci: source must be a plain heap table (got relkind %)', kind;
  END IF;
END;
$$;

-- SECURITY DEFINER COUNT reads packed aggregates, not the source heap.
-- SELECT privilege alone must not authorize bypassing RLS.
CREATE OR REPLACE FUNCTION tci_internal.require_rls_ok(p_source regclass)
RETURNS void
LANGUAGE plpgsql
STABLE
STRICT
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
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolbypassrls
  ) THEN
    RETURN;
  END IF;
  -- Owner bypasses RLS unless FORCE ROW LEVEL SECURITY
  IF NOT COALESCE(force_rls, false)
     AND pg_has_role(session_user, owner, 'MEMBER') THEN
    RETURN;
  END IF;
  RAISE EXCEPTION
    'pg_tci: RLS is enabled on % — TCI COUNT refused (fail closed; aggregates bypass row policies)',
    p_source
    USING ERRCODE = '42501';
END;
$$;

REVOKE ALL ON FUNCTION tci_internal.require_plain_heap(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION tci_internal.require_rls_ok(regclass) FROM PUBLIC;

-- Patch create() — reject partitions
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
  PERFORM tci_internal.require_plain_heap(source_table);
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

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_oid = source_table AND filter_col IS NULL
  ) THEN
    RAISE EXCEPTION 'pg_tci: index already exists for %', source_table;
  END IF;
  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes
    WHERE source_nsp = nsp AND source_rel = rel AND filter_col IS NULL
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

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild(source_table);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.create_filtered(
  source_table regclass,
  start_column name,
  end_column name,
  filter_column name,
  filter_value text,
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
  typid oid;
  canon text;
  is_null boolean;
  base tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_admin(source_table);
  PERFORM tci_internal.require_plain_heap(source_table);
  IF shard_count < 1 OR shard_count > 64 THEN
    RAISE EXCEPTION 'pg_tci: shard_count must be in [1,64]';
  END IF;
  IF chunk_bytes NOT IN (4096, 8192, 16384, 32768) THEN
    RAISE EXCEPTION 'pg_tci: chunk_bytes must be 4096|8192|16384|32768';
  END IF;
  IF cp_interval NOT IN (32, 64, 128) THEN
    RAISE EXCEPTION 'pg_tci: cp_interval must be 32|64|128';
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
  WHERE a.attrelid = source_table AND a.attname = start_column AND NOT a.attisdropped;
  SELECT a.atttypid INTO end_ty FROM pg_attribute a
  WHERE a.attrelid = source_table AND a.attname = end_column AND NOT a.attisdropped;
  IF start_ty IS NULL OR end_ty IS NULL THEN
    RAISE EXCEPTION 'pg_tci: columns %.%/% not found', source_table, start_column, end_column;
  END IF;
  IF start_ty <> 'timestamptz'::regtype OR end_ty <> 'timestamptz'::regtype THEN
    RAISE EXCEPTION 'pg_tci: start/end columns must be timestamptz';
  END IF;

  PERFORM 1 FROM pg_attribute
  WHERE attrelid = source_table AND attname = id_col AND NOT attisdropped;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_tci: id_col % not found on %', id_col, source_table;
  END IF;

  IF filter_column IN (start_column, end_column, id_col) THEN
    RAISE EXCEPTION 'pg_tci: filter_column must be distinct from start/end/id columns';
  END IF;

  SELECT * FROM tci_internal.resolve_filter_value(source_table, filter_column, filter_value)
    INTO typid, canon, is_null;

  SELECT * INTO base
  FROM tci_internal.indexes
  WHERE source_oid = source_table AND filter_col IS NULL;
  IF FOUND THEN
    IF base.start_col IS DISTINCT FROM start_column
       OR base.end_col IS DISTINCT FROM end_column THEN
      RAISE EXCEPTION
        'pg_tci: filtered start/end must match existing unfiltered index (% / %)',
        base.start_col, base.end_col;
    END IF;
    IF base.id_col IS DISTINCT FROM id_col THEN
      RAISE EXCEPTION
        'pg_tci: filtered id_col must match existing unfiltered index (%)',
        base.id_col;
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1 FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
      AND i.filter_col = filter_column
      AND i.filter_is_null = is_null
      AND (is_null OR i.filter_value IS NOT DISTINCT FROM canon)
  ) THEN
    RAISE EXCEPTION 'pg_tci: filtered index already exists for %(%=%)',
      source_table, filter_column,
      CASE WHEN is_null THEN 'NULL' ELSE canon END;
  END IF;

  INSERT INTO tci_internal.indexes(
    source_oid, source_nsp, source_rel, start_col, end_col,
    chunk_bytes, cp_interval, id_col, shard_count, published, valid,
    filter_col, filter_value, filter_typid, filter_is_null)
  VALUES (
    source_table, nsp, rel, start_column, end_column,
    chunk_bytes, cp_interval, id_col, shard_count, false, true,
    filter_column, canon, typid, is_null)
  RETURNING index_id INTO idx_id;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid = source_table AND tgname = 'tci_source_trig'
  ) THEN
    EXECUTE format(
      'CREATE TRIGGER tci_source_trig AFTER INSERT OR UPDATE OR DELETE ON %s
       FOR EACH ROW EXECUTE FUNCTION tci_internal.source_trig()',
      source_table);
  END IF;

  PERFORM tci.rebuild_filtered(source_table, filter_column, filter_value);
  PERFORM tci_internal.grant_admin_execute(owner_name);

  RETURN idx_id;
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at(source_table regclass, ts timestamptz)
RETURNS bigint
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, tci, pg_temp
AS $$
DECLARE
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  PERFORM tci_internal.require_rls_ok(source_table);
  idx := tci_internal.relink_source(source_table);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count(
      source_table, idx.start_col, idx.end_col, ts);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, ts)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, ts);
END;
$$;

CREATE OR REPLACE FUNCTION tci.count_at_filtered(
  source_table regclass,
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
  idx tci_internal.indexes%ROWTYPE;
BEGIN
  PERFORM tci_internal.require_select(source_table);
  PERFORM tci_internal.require_rls_ok(source_table);
  -- relink_filtered resolves OID or nsp/rel (dump/restore) and fail-closes if invalid
  idx := tci_internal.relink_filtered(source_table, filter_column, filter_value);

  IF NOT idx.valid OR NOT idx.published THEN
    RETURN tci_internal.native_count_filtered(
      source_table, idx.start_col, idx.end_col,
      idx.filter_col, idx.filter_typid, idx.filter_value, idx.filter_is_null,
      as_of);
  END IF;

  RETURN tci_internal.runs_prefix_sum(idx.index_id, as_of)
       + tci_internal.tail_sum_gen(idx.index_id, idx.generation, as_of);
END;
$$;

GRANT EXECUTE ON FUNCTION tci.count_at(regclass, timestamptz) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.count_at_filtered(regclass, timestamptz, name, text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION tci.create_filtered(regclass, name, name, name, text, int, int, name, int) TO PUBLIC;

-- Full storage accounting for all TCI-related relations on a source
CREATE OR REPLACE FUNCTION tci.storage_bytes(source_table regclass)
RETURNS TABLE (
  component text,
  index_id int,
  filter_col name,
  filter_value text,
  bytes bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, tci_internal, pg_temp
AS $$
DECLARE
  r record;
  b bigint;
BEGIN
  PERFORM tci_internal.require_select(source_table);

  SELECT pg_total_relation_size(source_table) INTO b;
  component := 'source_table_total'; index_id := NULL;
  filter_col := NULL; filter_value := NULL; bytes := b;
  RETURN NEXT;

  FOR r IN
    SELECT i.index_id, i.filter_col, i.filter_value, i.filter_is_null
    FROM tci_internal.indexes i
    WHERE i.source_oid = source_table
    ORDER BY i.filter_col NULLS FIRST, i.index_id
  LOOP
    SELECT
      COALESCE((SELECT sum(pg_column_size(c.payload))
                FROM tci_internal.chunks c WHERE c.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(t.*))
                  FROM tci_internal.tail t WHERE t.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(rn.*))
                  FROM tci_internal.runs rn WHERE rn.index_id = r.index_id), 0)
      + COALESCE((SELECT sum(pg_column_size(ch.*) - pg_column_size(ch.payload))
                  FROM tci_internal.chunks ch WHERE ch.index_id = r.index_id), 0)
      + COALESCE((SELECT pg_column_size(i.*)
                  FROM tci_internal.indexes i WHERE i.index_id = r.index_id), 0)
    INTO b;

    component := 'index_payload_est';
    index_id := r.index_id;
    filter_col := r.filter_col;
    filter_value := CASE WHEN r.filter_is_null THEN NULL ELSE r.filter_value END;
    bytes := COALESCE(b, 0);
    RETURN NEXT;
  END LOOP;

  -- Full tci_internal relation sizes (all indexes in this DB share these heaps)
  FOR r IN
    SELECT c.relname AS nm, pg_total_relation_size(c.oid) AS sz
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'tci_internal'
      AND c.relkind IN ('r', 'i', 't', 'm')
    ORDER BY 1
  LOOP
    component := 'tci_internal.' || r.nm;
    index_id := NULL; filter_col := NULL; filter_value := NULL;
    bytes := r.sz;
    RETURN NEXT;
  END LOOP;
END;
$$;

GRANT EXECUTE ON FUNCTION tci.storage_bytes(regclass) TO PUBLIC;

COMMENT ON FUNCTION tci.storage_bytes(regclass) IS
  'Full storage accounting: source + per-index estimates + all tci_internal relation sizes.';
COMMENT ON FUNCTION tci_internal.require_rls_ok(regclass) IS
  'Fail closed when RLS would be bypassed by SECURITY DEFINER TCI COUNT.';
COMMENT ON FUNCTION tci_internal.require_plain_heap(regclass) IS
  'Reject partitioned / non-heap sources.';
