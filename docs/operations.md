# Operations — pg_tci 0.1.12

## Install / upgrade

```bash
# from repo root
make PG_CONFIG=/path/to/pg18/pg_config clean && make && make install
psql -c "CREATE EXTENSION pg_tci;"          -- 0.1.12
psql -c "ALTER EXTENSION pg_tci UPDATE;"    -- along packaged path to default_version
```

Supported upgrades are the packaged scripts:

`0.1.0→…→0.1.10→0.1.12`

**Partitions:** `tci.create_partitioned` / `count_at_partitioned` fan out to leaves;
re-run after ATTACH. Packed index on the parent is not supported.
**RLS:** prefer `tci.count_at_safe` / `count_at_filtered_safe`.

There is no supported skip from an arbitrary unreleased research tree.

## When to seal

Seal when **tail cardinality** grows enough to dominate `count_at` latency.
Use `tci.stats` / `tci.shard_stats` (`n_tail`). Prefer `tci.seal_bounded`
under concurrency.

## When to compact

Compact when **live run count** grows (each run adds a chunk seek/decode).
Use `compact_pairwise` or `compact_budget` / `maintain(..., do_compact => true)`.

## Background maintenance worker (optional)

In `postgresql.conf` (restart required):

```text
shared_preload_libraries = 'pg_tci'
pg_tci.enable_maintenance_worker = on

# Multi-DB (preferred for fleets): one worker process per database
pg_tci.maintenance_databases = 'app,analytics'

# Or single DB (used when maintenance_databases is empty):
# pg_tci.maintenance_database = 'mydb'   # empty → postgres

pg_tci.maintenance_naptime = 60
pg_tci.maintenance_tail_target = 16384
pg_tci.maintenance_max_live_runs = 8
pg_tci.maintenance_max_seal_rows = 8192
```

Each worker runs `tci.maintain` for **unfiltered** published+valid indexes and
`tci.maintain_filters` for distinct sources that have filtered indexes.
Max **32** databases in `maintenance_databases`.

## External maintenance scheduler

Without preload, run from cron / systemd / job runner:

- `examples/maintain_cron.sh` — maintain + maintain_filters
- `examples/maintain_split.sh` — separate seal/compact transactions + timeouts
- `examples/maintain_seal_workers.sh` — multiple seal workers (advisory-serialized per shard)

```sql
SELECT * FROM tci.maintain(
  'sessions'::regclass,
  tail_target := 16384,
  max_live_runs := 8,
  budget_ms := 5000,
  max_active_writers := 8,
  max_seal_rows := 32768,
  do_compact := true,
  compact_mode := 'pairwise'
);
SELECT * FROM tci.capacity('sessions');
```

Writers take `FOR KEY SHARE`; seal/compact use per-shard advisory locks.
Rebuild/invalidate take the same advisory locks before catalog `FOR UPDATE`.

## Filtered indexes

```sql
SELECT tci.create_filtered('sessions', 'started_at', 'ended_at', 'segment', 'enterprise');
SELECT tci.count_at_filtered('sessions', now(), 'segment', 'enterprise');
SELECT * FROM tci.maintain_filters('sessions', 16384, 8);
SELECT * FROM tci.list_filters('sessions');
SELECT * FROM tci.filter_fit_estimate('sessions', 'segment');  -- cardinality hint
SELECT * FROM tci.storage_bytes('sessions');
```

`maintain_filters` relinks filtered catalog rows (post-restore OID drift) before
seal/compact.

## Write amplification / capacity

TCI captures deltas on source DML into `tci_internal.tail`, then seals into packed
chunks. Under sustained writes:

| Signal | Action |
|--------|--------|
| `n_tail` rising | Increase maintain frequency / `max_seal_rows`; check locks |
| `capacity_ok = false` | Seal lagging ingest — reduce writers or raise seal budget |
| `live_runs` high | Compact; decode cost grows with run count |
| WAL / disk growth on `tci_internal.*` | Ensure autovacuum keeps up after seal `DELETE`s |

Suggested alert thresholds (tune per estate):

- page if `n_tail > 100000` for >5 minutes  
- page if `capacity_ok = false`  
- page if `valid = false` or `published = false` (use `tci.list_invalid`)  

```sql
SELECT * FROM tci.health('sessions');
SELECT * FROM tci.list_invalid(NULL);
```

Bounded average tail growth still does **not** guarantee low p95 during write
bursts or while compact/vacuum contend for I/O. Under **50 readers + high write**
stress, spikes remain a known limit (research v16–v21).

## Dump / restore

```bash
# After pg_restore into a DB that has the extension + catalog:
PGDATABASE=restored ./examples/post_restore_rebuild.sh
# or:
psql -c "SELECT * FROM tci.rebuild_invalid(NULL);"
```

OID relink invalidates indexes; COUNT stays exact via native fallback until rebuild.

## Privileges (0.1.10)

- Read APIs (`count_at`, `count_at_filtered`, `stats`, `shard_stats`, `capacity`,
  `health`, `list_filters`, `list_invalid`, `storage_bytes`, `filter_fit_estimate`):
  PUBLIC EXECUTE + `require_select` (+ RLS fail-closed on COUNT)
- Admin APIs: **no** PUBLIC EXECUTE; `tci.create` / `create_filtered` grant
  EXECUTE to the table owner; DBAs may `SELECT tci.grant_admin('role')`
- `rebuild_invalid` is admin (via `admin_procedures`)

## Monitoring checklist

| Signal | API / catalog |
|--------|----------------|
| Tail size | `tci.stats` / `shard_stats` / `health` |
| Live runs | `tci.stats` / `health` |
| Seal throughput | `tci.capacity` / `health` |
| Validity | `stats` / `health` / `list_invalid` |
| Recent maint | `tci.maint_history` |
| Shard backlog | `shard_stats` |
| Filter fit | `filter_fit_estimate` |

## VACUUM / WAL / storage

- Autovacuum must keep up on `tci_internal.tail` and `chunks` after seal/compact `DELETE`s
- Packed runs reduce storage and merge WAL vs row-based IAR (research evidence)
- LOGGED tables participate in normal WAL; size WAL retention accordingly

## Rebuild / restore

- Schema/column changes: DDL event trigger invalidates; call `tci.rebuild` /
  `rebuild_filtered` / `rebuild_invalid` after fixing
- Troubleshooting: `invalidate` → native path; `rebuild*` → packed path;
  compare under one snapshot

## Upgrading the extension

1. Install new package files (`make install`)
2. `ALTER EXTENSION pg_tci UPDATE;`
3. Smoke: `SELECT extversion FROM pg_extension WHERE extname='pg_tci';`
4. Spot-check `count_at` vs native; run `maintain` if tails grew during upgrade window
