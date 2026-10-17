# Database Migration Strategy

## Principle

Schema changes are **versioned and deterministic** from day one. No ad-hoc
`ALTER TABLE` drift, no "works on my machine" schema. Every change is a
numbered migration applied in order inside a transaction.

## Current state

Two components persist to SQLite today:

- `AuditLog(path)` — `audit` table (hash-chained events).
- `ApprovalQueue(path)` — `approvals` table (durable DEFER_HUMAN queue).

Both create their tables with `CREATE TABLE IF NOT EXISTS` in `__init__`.
That is acceptable for a reference build but is **not** a migration strategy:
it cannot rename a column, add an index, or backfill data.

## The seam

`aegis/core/migrations.py` provides `run_migrations(conn, migrations)`:

```python
from aegis.core.migrations import run_migrations

MIGRATIONS = [
    (1, "CREATE TABLE approvals (id TEXT PRIMARY KEY, status TEXT, ...);"),
    (2, "ALTER TABLE approvals ADD COLUMN approver TEXT;"),
]
run_migrations(conn, MIGRATIONS)
```

It records applied versions in `schema_migrations`, skips already-applied
versions, and rejects out-of-order files. Re-running is a no-op.

## Target state (production)

1. **Move to Postgres** (the `database_url` setting already exists in
   `config.py`). SQLite is single-node and unsuitable for horizontal scaling
   (Risk B).
2. **Use Alembic** for migrations. The `run_migrations` seam is a stdlib
   stand-in; the migration *files* carry over to Alembic unchanged in spirit.
3. **Version-tag stored formats** before the first production deployment —
   the audit/attestation/Merkle formats changed during development (see
   `AUDIT_REPORT.md` compatibility note).

## Rules

- One logical change per migration.
- Migrations are forward-only in production (no destructive down-migrations
  without an explicit, reviewed backfill).
- Every migration is covered by a test that applies it to a fresh DB and
  re-applies it (idempotency).
- Schema changes to the audit log require a signed attestation of the change
  (the audit log's own integrity must never be broken by a migration).
