#!/usr/bin/env bash
# After pg_restore: rebuild invalid or unpublished TCI indexes (packed path).
# Prefers tci.rebuild_invalid (0.1.10+); falls back to per-index SQL on older builds.
# Usage:
#   PGHOST=... PGPORT=... PGDATABASE=... ./post_restore_rebuild.sh
#   DRY_RUN=1 ./post_restore_rebuild.sh
set -euo pipefail

: "${PGHOST:=/tmp}"
: "${PGPORT:=5432}"
: "${PGDATABASE:=postgres}"
: "${DRY_RUN:=0}"

export PGHOST PGPORT PGDATABASE
PSQL=(psql -v ON_ERROR_STOP=1)

echo "== pg_tci post-restore rebuild (db=${PGDATABASE}) =="

"${PSQL[@]}" -c "SELECT * FROM tci.list_invalid(NULL);" 2>/dev/null || \
"${PSQL[@]}" -c "
SELECT index_id,
       format('%I.%I', source_nsp, source_rel) AS source,
       filter_col, filter_value, filter_is_null, published, valid
  FROM tci_internal.indexes
 WHERE NOT valid OR NOT published
 ORDER BY index_id;
"

if [ "${DRY_RUN}" = "1" ]; then
  echo "DRY_RUN=1 — listing only"
  exit 0
fi

if "${PSQL[@]}" -At -c "SELECT to_regprocedure('tci.rebuild_invalid(regclass)') IS NOT NULL" | grep -q t; then
  echo "Using tci.rebuild_invalid()"
  "${PSQL[@]}" -c "SELECT * FROM tci.rebuild_invalid(NULL);"
else
  echo "tci.rebuild_invalid unavailable — legacy per-index rebuild"
  while IFS= read -r sql; do
    [ -z "${sql}" ] && continue
    echo "RUN: ${sql}"
    "${PSQL[@]}" -c "${sql}"
  done < <("${PSQL[@]}" -At -c "
SELECT CASE
  WHEN filter_col IS NULL THEN
    format('SELECT tci.rebuild(%L::regclass);',
           format('%I.%I', source_nsp, source_rel))
  WHEN filter_is_null THEN
    format('SELECT tci.rebuild_filtered(%L::regclass, %L, NULL);',
           format('%I.%I', source_nsp, source_rel), filter_col)
  ELSE
    format('SELECT tci.rebuild_filtered(%L::regclass, %L, %L);',
           format('%I.%I', source_nsp, source_rel), filter_col, filter_value)
END
  FROM tci_internal.indexes
 WHERE NOT valid OR NOT published
 ORDER BY index_id;
")
fi

echo "== health (distinct sources) =="
while IFS= read -r src; do
  [ -z "${src}" ] && continue
  "${PSQL[@]}" -c "SELECT * FROM tci.health('${src}'::regclass);"
done < <("${PSQL[@]}" -At -c "
SELECT DISTINCT format('%I.%I', source_nsp, source_rel)
  FROM tci_internal.indexes
 ORDER BY 1;
")

echo "Done."
