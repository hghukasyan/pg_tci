-- pg_tci 0.1.10 → 0.1.11
-- Allow TCI on partition *leaves* (heap children). Partitioned *parents*
-- (relkind=p) remain rejected — no parent-level aggregate across partitions.

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
  -- Partitioned parent: unsupported (no cross-partition TCI)
  IF kind = 'p' THEN
    RAISE EXCEPTION
      'pg_tci: partitioned parent tables are not supported (source %); index each leaf partition instead',
      p_source
      USING ERRCODE = '0A000';
  END IF;
  -- Ordinary heap, including partition leaves (relkind=r, relispartition=true)
  IF kind <> 'r' THEN
    RAISE EXCEPTION
      'pg_tci: source must be a heap table or partition leaf (got relkind %)', kind;
  END IF;
END;
$$;

COMMENT ON FUNCTION tci_internal.require_plain_heap(regclass) IS
  'Reject partitioned parents and non-heap sources; partition leaves allowed.';

COMMENT ON SCHEMA tci IS
  'pg_tci public API (0.1.11 — partition leaf sources allowed)';
