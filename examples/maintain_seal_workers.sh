#!/usr/bin/env bash
# pg_tci v11 — multiple seal workers (advisory-serialized per index; writers unbound)
# Usage: SOURCE_TABLE=sessions BATCH=32768 WORKERS=2 INTERVAL_MS=50 ./maintain_seal_workers.sh
set -euo pipefail
: "${PGHOST:=/tmp}"
: "${PGPORT:=55432}"
: "${PGDATABASE:=pg_tci_v11}"
: "${SOURCE_TABLE:=sessions}"
: "${BATCH:=32768}"
: "${WORKERS:=2}"
: "${INTERVAL_MS:=50}"
: "${COMPACT_EVERY:=16}"
: "${LOCK_TIMEOUT:=2s}"
: "${STATEMENT_TIMEOUT:=15s}"

seal_loop() {
  local id="$1"
  local n=0
  while true; do
    psql -v ON_ERROR_STOP=0 -qAt <<SQL >/dev/null || true
SET lock_timeout = '${LOCK_TIMEOUT}';
SET statement_timeout = '${STATEMENT_TIMEOUT}';
SELECT tci.seal_bounded('${SOURCE_TABLE}'::regclass, ${BATCH});
SQL
    n=$((n+1))
    if (( COMPACT_EVERY > 0 && n % COMPACT_EVERY == 0 && id == 0 )); then
      psql -v ON_ERROR_STOP=0 -qAt <<SQL >/dev/null || true
SET lock_timeout = '${LOCK_TIMEOUT}';
SET statement_timeout = '${STATEMENT_TIMEOUT}';
SELECT tci.compact_pairwise('${SOURCE_TABLE}'::regclass);
SQL
    fi
    sleep "$(awk "BEGIN{print ${INTERVAL_MS}/1000}")"
  done
}

for i in $(seq 0 $((WORKERS-1))); do
  seal_loop "$i" &
done
wait
