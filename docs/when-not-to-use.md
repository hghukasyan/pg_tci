# When **not** to use pg_tci (yet)

Use this before installing. If any row matches, skip or wait.

| If you need… | Then |
|--------------|------|
| Production GA / formal MVCC proof | Wait — 0.1.12 is **external preview** |
| PostgreSQL ≤17 | Unsupported (validated target is **18**) |
| Managed Postgres that **blocks custom extensions** (many RDS/Aurora/Cloud SQL setups) | Cannot install (`superuser` + `.so`) |
| Transparent speedup of arbitrary `SELECT COUNT(*)` | Not an Index AM; must call `tci.count_at*` |
| Arbitrary `WHERE` / JOIN / expressions | Unsupported |
| Partitioned **parent** packed index | Use `create_partitioned` / `count_at_partitioned` (fan-out); no parent packed store |
| Expect packed COUNT under RLS | Packed `count_at*` **refuses**; use `count_at*_safe` (native under policies) |
| High-cardinality equality filters (tens–hundreds of keys) | Native often wins — measure first |
| Zero ops / no maintenance under sustained writes | Tail grows; latency degrades without seal/compact |
| Approximate real-time metrics / TSDB replacement | Wrong product category |

**Good fit (short):** self-hosted PostgreSQL 18, plain heap interval table, exact
coverage `COUNT` at timestamp *t*, optional **few** registered equality filters,
willingness to change call sites and run maintenance.

See also [`limitations.md`](limitations.md).
