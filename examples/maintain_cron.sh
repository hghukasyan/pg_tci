#!/usr/bin/env bash
# External scheduler example for tci.maintain + tci.maintain_filters.
# No shared_preload_libraries required.
#
# Cron (every minute):
#   * * * * * PGHOST=/tmp PGPORT=55432 PGDATABASE=mydb /path/to/maintain_cron.sh
set -euo pipefail

: "${PGHOST:=/tmp}"
: "${PGPORT:=55432}"
: "${PGDATABASE:=postgres}"
: "${TAIL_TARGET:=16384}"
: "${MAX_LIVE_RUNS:=8}"
: "${BUDGET_MS:=5000}"

export PGHOST PGPORT PGDATABASE

# Unfiltered indexes
psql -v ON_ERROR_STOP=1 -Atc \
  "SELECT format('%I.%I', source_nsp, source_rel)
     FROM tci_internal.indexes
    WHERE published AND valid
      AND filter_col IS NULL
    ORDER BY index_id;" \
| while IFS= read -r tbl; do
  [ -z "${tbl}" ] && continue
  psql -v ON_ERROR_STOP=1 -c \
    "SELECT * FROM tci.maintain('${tbl}'::regclass, ${TAIL_TARGET}, ${MAX_LIVE_RUNS}, ${BUDGET_MS});"
done

# Distinct sources that have filtered indexes
psql -v ON_ERROR_STOP=1 -Atc \
  "SELECT DISTINCT format('%I.%I', source_nsp, source_rel)
     FROM tci_internal.indexes
    WHERE published AND valid
      AND filter_col IS NOT NULL
    ORDER BY 1;" \
| while IFS= read -r tbl; do
  [ -z "${tbl}" ] && continue
  psql -v ON_ERROR_STOP=1 -c \
    "SELECT * FROM tci.maintain_filters('${tbl}'::regclass, ${TAIL_TARGET}, ${MAX_LIVE_RUNS});"
done
