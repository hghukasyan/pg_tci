# Correctness — pg_tci 0.1.8

## Guarantees

- When `published AND valid`, `tci.count_at` is intended to match native
  `COUNT` of intervals covering `ts` under the **same** snapshot.
- When invalid/unpublished, the API falls back to native `COUNT` (fail closed
  on the fast path; never silently returns packed stale data).
- Corrupted TCIP payloads ERROR out of the decoder (fail closed).

## Semantics

- `[start, end)` exclusive end
- `ended_at IS NULL` → open-ended (still active)

## Snapshot discipline

Do **not** compare unrelated `READ COMMITTED` statements from different
transactions and treat mismatches as TCI bugs. Prefer:

```sql
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT tci.count_at('sessions', $1);
SELECT count(*) FROM sessions s
 WHERE s.started_at <= $1
   AND (s.ended_at IS NULL OR s.ended_at > $1);
COMMIT;
```

## Known limitations

- Not a formal proof of MVCC correctness for all isolation anomalies.
- Packaged `make installcheck` includes `mvcc` (RR same-snapshot + invalidate)
  and isolation specs (`count_rr_insert`, `seal_during_rr`).
  SERIALIZABLE + seal/compact under high contention is only lightly covered
  (additional harnesses under `benchmark/`).
- Event triggers invalidate on `ALTER TABLE`; some DDL paths still need
  manual `tci.rebuild`.
- After dump/restore, verify with `tci.stats` and spot-check vs native;
  OID rematch invalidates pending rebuild.

Passing finite tests ≠ formal MVCC proof.
