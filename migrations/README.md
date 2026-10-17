# Alembic migrations

Production data-layer migrations live here. The reference build uses the
stdlib `aegis.core.migrations.run_migrations` seam (see `docs/migrations.md`);
Alembic is the production path once Postgres is provisioned.

## Bootstrap

```bash
pip install alembic psycopg2-binary
alembic init migrations          # already scaffolded
alembic revision --autogenerate -m "create approvals"
alembic upgrade head
```

## Rules

- One logical change per revision.
- Forward-only in production.
- Audit-log schema changes require a signed attestation of the change.
