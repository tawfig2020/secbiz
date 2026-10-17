"""Versioned schema migrations (stdlib-only).

The approval queue and audit log use SQLite today; production will move to
Postgres. Schema changes must be versioned from day one so an upgrade is a
deterministic, auditable sequence — never ad-hoc `ALTER TABLE` drift.

A migration is a `(version, up_sql)` pair. `run_migrations` applies every
pending migration inside a transaction and records the applied version in a
`schema_migrations` table, so re-running is a no-op and out-of-order files
are rejected.

    MIGRATIONS = [
        (1, "CREATE TABLE approvals (...);"),
        (2, "ALTER TABLE approvals ADD COLUMN approver TEXT;"),
    ]
    run_migrations(conn, MIGRATIONS)
"""
from __future__ import annotations

import sqlite3
from typing import Iterable


def _ensure_meta(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY,"
        " applied_at REAL NOT NULL)")


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    _ensure_meta(conn)
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {r[0] for r in rows}


def run_migrations(conn: sqlite3.Connection,
                   migrations: Iterable[tuple[int, str]]) -> list[int]:
    """Apply pending migrations in order. Returns the versions applied."""
    import time

    _ensure_meta(conn)
    done = applied_versions(conn)
    applied: list[int] = []
    for version, up_sql in sorted(migrations, key=lambda m: m[0]):
        if version in done:
            continue
        if version <= max(done, default=0):
            raise ValueError(
                f"migration {version} is out of order; already at "
                f"{max(done, default=0)}")
        try:
            conn.execute("BEGIN")
            conn.executescript(up_sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at)"
                " VALUES (?, ?)", (version, time.time()))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        applied.append(version)
    return applied


__all__ = ["applied_versions", "run_migrations"]
