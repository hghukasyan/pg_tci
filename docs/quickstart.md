# Quickstart — pg_tci 0.1.7-preview

```bash
export PG_CONFIG=$(which pg_config)
# from repo root
make clean && make && make install
```

```sql
CREATE EXTENSION pg_tci;

CREATE TABLE sessions (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL,
  ended_at timestamptz
);

INSERT INTO sessions(started_at, ended_at) VALUES
  (now() - interval '1 hour', now() + interval '1 hour'),
  (now() - interval '30 minutes', NULL);

SELECT tci.create('sessions'::regclass, 'started_at', 'ended_at');
SELECT tci.count_at('sessions'::regclass, now());
SELECT * FROM tci.stats('sessions'::regclass);
```

Full example: `examples/basic_usage.sql`.
