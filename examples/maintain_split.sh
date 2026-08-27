#!/usr/bin/env bash
# Split maintenance into separate short transactions (v10).
# Uses lock_timeout + statement_timeout as hard budgets.
set -euo pipefail

: "${PGHOST:=/tmp}"
: "${PGPORT:=55432}"
: "${PGDATABASE:=postgres}"
: "${TABLE:=public.sessions}"
: "${TAIL_TARGET:=4096}"
: "${MAX_SEAL_ROWS:=8192}"
: "${MAX_LIVE_RUNS:=8}"
: "${LOCK_TIMEOUT:=1s}"
: "${SEAL_STMT_TIMEOUT:=5s}"
: "${COMPACT_STMT_TIMEOUT:=5s}"
: "${MAX_COMPACT_ROUNDS:=4}"

export PGHOST PGPORT PGDATABASE

# Transaction A — bounded seal only
psql -v ON_ERROR_STOP=1 <<SQL
SET lock_timeout = '${LOCK_TIMEOUT}';
SET statement_timeout = '${SEAL_STMT_TIMEOUT}';
SELECT * FROM tci.maintain(
  '${TABLE}'::regclass,
  tail_target := ${TAIL_TARGET},
  max_live_runs := ${MAX_LIVE_RUNS},
  budget_ms := 1500,
  max_active_writers := 64,
  max_seal_rows := ${MAX_SEAL_ROWS},
  do_compact := false,
  compact_mode := 'pairwise'
);
SQL

# Transactions B.. — pairwise compact until under max_live_runs
for _ in $(seq 1 "${MAX_COMPACT_ROUNDS}"); do
  live=$(psql -Atc "SELECT live_runs FROM tci.stats('${TABLE}'::regclass);" || echo 0)
  if [ "${live:-0}" -le "${MAX_LIVE_RUNS}" ]; then
    break
  fi
  psql -v ON_ERROR_STOP=1 <<SQL || true
SET lock_timeout = '${LOCK_TIMEOUT}';
SET statement_timeout = '${COMPACT_STMT_TIMEOUT}';
SELECT tci.compact_pairwise('${TABLE}'::regclass);
SQL
done
