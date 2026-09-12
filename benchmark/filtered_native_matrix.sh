#!/usr/bin/env bash
# Focused filter matrix for native filtered TCI decision gates.
# Runs read-latency cells + short mixed loads. Writes JSON summary.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT_DIR=$ROOT/out
mkdir -p "$OUT_DIR" "$ROOT/results"
export PGHOST=${PGHOST:-/tmp} PGPORT=${PGPORT:-55432} PGUSER=${PGUSER:-$(whoami)}
export PATH="/opt/homebrew/opt/postgresql@18/bin:$PATH"
SUMMARY=$OUT_DIR/filtered_native_matrix.jsonl
: > "$SUMMARY"

run_cell() {
  local rows=$1 segs=$2 skew=$3 mode=$4
  echo "=== CELL rows=$rows segs=$segs skew=$skew mode=$mode ==="
  ROWS=$rows SEGMENTS=$segs SKEW=$skew MODE=$mode LOOPS=150 WARM=40 \
    PGDATABASE=tci_filt_bench \
    bash "$ROOT/filtered_native.sh" | tee /tmp/filt_cell.out

  # Parse p95 lines into jsonl
  python3 - <<PY >> "$SUMMARY"
import json, re, sys
text=open("/tmp/filt_cell.out").read()
rows={}
for line in text.splitlines():
    m=re.match(r'\s*(mode|native)\s+\|\s+([\d.]+)\s+\|\s+([\d.]+)\s+\|\s+([\d.]+)', line)
    if m:
        rows[m.group(1)]={"p50":float(m.group(2)),"p95":float(m.group(3)),"p99":float(m.group(4))}
print(json.dumps({
  "kind":"read",
  "rows":$rows,"segments":$segs,"skew":"$skew","mode":"$mode",
  "latency":rows
}))
PY
}

# Core read cells (100k)
for mode in native filtered_tci slice_tci; do
  run_cell 100000 4 uniform "$mode"
done
for mode in native filtered_tci slice_tci; do
  run_cell 100000 4 hot90 "$mode"
done
for mode in native filtered_tci; do
  run_cell 100000 16 uniform "$mode"
done
# Cardinality stress (filtered only + native)
for segs in 64 256; do
  for mode in native filtered_tci; do
    run_cell 100000 "$segs" uniform "$mode"
  done
done
# 1M smoke for promising filtered
run_cell 1000000 4 uniform filtered_tci
run_cell 1000000 4 uniform native

# Mixed short cells
for mode in filtered_tci native slice_tci; do
  echo "=== MIXED mode=$mode ==="
  ROWS=50000 SEGMENTS=4 SKEW=hot90 MODE=$mode READERS=8 WRITERS=4 \
    WARMUP_S=5 RUN_S=15 MAINT=1 PGDATABASE=tci_filt_mixed \
    python3 "$ROOT/filtered_native_mixed.py" | tee /tmp/filt_mixed.out
  python3 - <<PY >> "$SUMMARY"
import json
print(json.dumps({"kind":"mixed", **json.load(open("$ROOT/out/filtered_native_mixed_$mode.json"))}))
PY
done

# Longer mixed for filtered_tci if short cell looked good
echo "=== MIXED 10min filtered_tci ==="
ROWS=50000 SEGMENTS=4 SKEW=hot90 MODE=filtered_tci READERS=8 WRITERS=4 \
  WARMUP_S=10 RUN_S=600 MAINT=1 PGDATABASE=tci_filt_mixed_long \
  python3 "$ROOT/filtered_native_mixed.py" | tee /tmp/filt_mixed_long.out
cp "$ROOT/out/filtered_native_mixed_filtered_tci.json" \
   "$ROOT/out/filtered_native_mixed_filtered_tci_10m.json"

echo "matrix complete → $SUMMARY"
