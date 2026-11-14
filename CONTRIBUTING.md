# Contributing

Thank you for interest in **pg_tci**. This is a **free open-source external
preview** extension (not production GA) under the PostgreSQL License.

## Development setup

```bash
export PG_CONFIG=/path/to/postgresql@18/bin/pg_config
make clean && make && make install
make installcheck
```

Use a disposable PostgreSQL 18 instance for experiments. Do not point harnesses
at production data.

## Expectations

- Keep TCIP v1 on-disk format stable unless introducing a new codec version
- Do not add Index Access Methods or planner hooks without an explicit design review
- Prefer fail-closed behavior over stale counts
- Include regression coverage for correctness fixes
- Document benchmark conditions honestly (no fabricated numbers)

## Pull requests

- One logical change per PR when practical
- Update `CHANGELOG.md` for user-visible changes
- Run `make installcheck` before requesting review

## License

Contributions are accepted under the PostgreSQL License (see `LICENSE`).
