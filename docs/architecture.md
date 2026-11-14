# Architecture — pg_tci 0.1.7-preview

## Separation of concerns

| Layer | Objects |
|-------|---------|
| **Public API** | `tci.create`, `count_at`, `stats`, `shard_stats`, `seal` / `seal_bounded`, `compact` / `compact_pairwise` / `compact_budget`, `maintain`, `invalidate`, `rebuild`, `capacity` / `capacity_reset`, `set_shard_count` |
| **Internal storage** | `tci_internal.{indexes,runs,chunks,tail}` (+ maint/capacity helpers) |
| **Compression codec** | TCIP v1 via `tci_internal.pack_entries` / `chunk_prefix_at` / `unpack_entries` |
| **Sealing** | Consume generation-scoped tail into packed run(s); sharded / bounded variants |
| **Merging** | Compact live runs; retire + DELETE old chunks atomically |
| **Metadata** | `indexes.published`, `indexes.valid`, `generation`, `shard_count` |
| **Monitoring** | `tci.stats`, `tci.shard_stats`, `tci.capacity` |

No `CREATE ACCESS METHOD`. No planner hooks. No per-run physical relations.

## COUNT path (published ∧ valid)

1. **Fused** set-based prefix over live runs (`runs_prefix_sum`): one candidate
   chunk per run → C decode → sum `prefix_before + decode`
2. Add snapshot-visible **tail** deltas for the current `generation`
   (`tail_sum_gen`)
3. Result = exact active interval count for `[start, end)` under the caller’s snapshot

If `NOT valid OR NOT published` → **native SQL COUNT** (never return stale packed aggregates).

## MVCC invariants (required for exactness)

1. Source table is the source of truth.
2. Triggers append compensating ±1 boundary deltas to `tail` for the published generation.
3. Seal/merge replace sealed state with `INSERT` new run/chunks + `DELETE` obsolete rows in one transaction.
4. Readers use normal PostgreSQL snapshot visibility on `runs`/`chunks`/`tail`/`indexes`.
5. Interval semantics: `start ≤ ts AND (end IS NULL OR end > ts)`.

Finite passing tests ≠ formal MVCC proof.

## Correctness fixes retained through 0.1.7

- Rebuild/seal generation race: rebuild/invalidate acquire the same advisory
  shard locks before catalog `FOR UPDATE` (v12)
- Shard routing stability + advisory key isolation (v13)
- UPDATE delta coalescing in the source trigger
- Bounded sealing; PK-based DELETE optimization on seal (v14)
- Fused run aggregation in `count_at` (v15 / 0.1.7)
- Restore OID relinking with invalidation (`relink_source`)

## TCIP v1 format contract

See `include/pg_tci.h`. Summary:

- Magic `TCIP` (LE `0x50494354`), version `1`
- Fixed 24-byte header + 24-byte checkpoints
- Entry stream: unsigned varint ∆ts + zigzag varint delta
- Timestamps: int64 µs since PostgreSQL epoch `2000-01-01 00:00:00+00`
- Checkpoint intervals: 32 / 64 / 128 only
- Corruption → ERROR (fail closed)

**Do not change TCIP v1 on-disk layout in preview without a new versioned codec.**
