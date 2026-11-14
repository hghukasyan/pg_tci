# Security Policy

## Supported versions

Only the current packaged line (**0.1.12**) receives fixes. Older preview
minors should upgrade via sequential `ALTER EXTENSION` scripts.

Status: **external preview** — not production GA.

## Reporting a vulnerability

Please report security issues privately via **GitHub Security Advisories** on
this repository (preferred). If Advisories are unavailable, open a private
maintainer contact through the repository’s security contact settings.

Include:

- PostgreSQL version
- Extension version (`SELECT extversion FROM pg_extension WHERE extname='pg_tci'`)
- Minimal reproduction
- Impact (privilege bypass, incorrect counts as integrity issue, crash, etc.)

## Severity (community / best effort)

| Severity | Examples |
|----------|----------|
| **S1** | Incorrect `count_at` / `count_at_filtered` vs same-snapshot native; privilege bypass; crash on trusted input |
| **S2** | Maintenance stuck; severe latency regression with capacity signals red; restore left indexes invalid without documented path |
| **S3** | Docs mismatch; non-critical install friction |
| **S4** | Questions / feature requests |

There is no paid support SLA. Response is best-effort from maintainers.

## Security notes for operators

- Extension install requires **superuser** (`pg_tci.control`: `superuser = true`)
- Public APIs use `SECURITY DEFINER` with pinned `search_path`
- Authorization uses **`session_user`** (table owner / `TRIGGER` / `SELECT`)
- Schema `tci_internal` is not granted to `PUBLIC`
- RLS enabled without bypass → TCI COUNT **refused** (fail closed); use `count_at*_safe` for INVOKER native under policies
- Treat incorrect coverage counts under a claimed exact API as **S1**
