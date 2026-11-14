# Benchmarks — pg_tci 0.1.12

Representative measurements on disposable PostgreSQL 18 clusters.
**Not** SLAs. Reproduce via `benchmark/` scripts.

## Unfiltered (historical preview cells)

### Warm microbench (~100k intervals)

| Method | Warm COUNT p95 |
|--------|----------------|
| TCI | ~0.046 ms |
| Native | ~2.06 ms |

### Concurrent / mixed (1M; research v21)

| Cell | TCI p95 | Native p95 |
|------|---------|------------|
| 50 readers read-only | ~31 ms | ~580 ms |
| 50 readers + ~5k writes/s | ~338 ms | ~926 ms |

## Native filtered TCI

### Warm filtered COUNT p95 (selected)

| rows | filters | skew | filtered_tci | native | advantage |
|------|---------|------|-------------:|-------:|----------:|
| 100k | 4 | uniform | 0.105 ms | 0.972 ms | ~9× |
| 100k | 4 | hot90 | 0.289 ms | 3.971 ms | ~14× |
| 1M | 4 | uniform | 0.314 ms | 11.7 ms | ~37× |
| 100k | 256 | uniform | 0.123 ms | 0.059 ms | native wins |

### Fair storage + write (100k / 4 / uniform, hardening cell)

| mode | source+idx | extra | write cycles/s | read p95 |
|------|------------|-------|----------------|----------|
| filtered_tci | ~11.1 MB | tci_internal ~0.80 MB | ~3.1k | 0.165 ms |
| slice_tci | ~11.0 MB | slices ~9.4 MB + tci ~1.1 MB | ~3.3k | 0.130 ms |
| native | ~11.1 MB | — | ~8.6k | 0.784 ms |

### Mixed 8R/4W hot90 (15 s) / 10‑min sustained

| mode | read p95 | writes/s | RR mismatches |
|------|----------|----------|---------------|
| filtered_tci (15 s) | 3.21 ms | ~296 | 0 |
| native (15 s) | 5.93 ms | ~318 | 0 |
| slice_tci (15 s) | 2.84 ms | ~298 | 0 |
| filtered_tci (10 min) | 6.22 ms | ~290 | 0 |

## Reproduce

```bash
ROWS=100000 SEGMENTS=4 SKEW=uniform MODE=filtered_tci ./benchmark/filtered_native.sh
ROWS=50000 SEGMENTS=4 SKEW=hot90 MODE=filtered_tci READERS=8 WRITERS=4 \
  WARMUP_S=5 RUN_S=15 MAINT=1 python3 benchmark/filtered_native_mixed.py
```
