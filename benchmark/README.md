# Benchmarks

Optional harnesses for local reproduction. Not run in CI by default.

## Prerequisites

- PostgreSQL 18 with `pg_tci` installed
- Disposable database (never production)

```bash
export PGHOST=/tmp PGPORT=55432 PGUSER=$USER PGDATABASE=tci_bench
createdb tci_bench
```

## Smoke (correctness + latency)

```bash
./smoke.sh
```

## Correctness stress

```bash
psql -d tci_bench -v ON_ERROR_STOP=1 -f correctness_stress.sql
```

## Filtered native matrix

```bash
./filtered_native.sh
./filtered_native_matrix.sh
```

## Segment spike

```bash
./segment_spike.sh
```

Published numbers: [`docs/benchmarks.md`](../docs/benchmarks.md).
