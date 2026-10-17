"""Shared durable store seams (Risk B).

The reference build keeps nonces, usage meters, API keys, and rate limits
in-memory or single-node SQLite. Production needs shared stores so the system
can run multi-instance:

    PostgresStore      nonces / usage / API keys (and any small KV)
    RedisRateLimiter   sliding-window rate limits

Both are optional-dependency adapters: they import their driver lazily and
raise `InfraError` (never silently fall back) if the driver is missing or the
connection fails. This is the seam; provisioning the actual Postgres/Redis is
an operational step (see `docs/operations.md`).
"""
from __future__ import annotations

import time

from aegis.core.errors import InfraError
from aegis.semantic_gateway.rate_limiter import LimitResult


class PostgresStore:
    """Durable key-value store backed by Postgres (optional psycopg2)."""

    def __init__(self, dsn: str, table: str = "aegis_kv") -> None:
        self._dsn = dsn
        self._table = table
        self._conn = None

    def _connect(self):
        if self._conn is not None:
            return self._conn
        try:
            import psycopg2  # optional dependency
        except ImportError as exc:
            raise InfraError(
                "psycopg2 is required for PostgresStore; "
                "pip install psycopg2-binary") from exc
        try:
            self._conn = psycopg2.connect(self._dsn)
            with self._conn.cursor() as cur:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {self._table} ("
                    " key TEXT PRIMARY KEY,"
                    " value TEXT NOT NULL,"
                    " updated_at TIMESTAMPTZ NOT NULL DEFAULT now())")
            self._conn.commit()
        except Exception as exc:
            raise InfraError(f"PostgresStore connect failed: {exc}") from exc
        return self._conn

    def get(self, key: str) -> str | None:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(f"SELECT value FROM {self._table} WHERE key=%s",
                        (key,))
            row = cur.fetchone()
        return row[0] if row else None

    def put(self, key: str, value: str) -> None:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self._table} (key, value, updated_at) "
                "VALUES (%s, %s, now()) "
                "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, "
                "updated_at=now()", (key, value))
        conn.commit()

    def delete(self, key: str) -> None:
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {self._table} WHERE key=%s", (key,))
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


class RedisRateLimiter:
    """Sliding-window rate limiter backed by Redis (optional redis-py).

    Mirrors the in-memory `RateLimiter` interface: `allow(source_id)` returns
    a `LimitResult`. Uses a sorted set per source plus a global set.
    """

    def __init__(self, url: str, per_source_max: int = 120,
                 window_seconds: float = 60.0, global_max: int = 5000) -> None:
        self._url = url
        self.per_source_max = per_source_max
        self.window = window_seconds
        self.global_max = global_max
        self._client = None

    def _redis(self):
        if self._client is not None:
            return self._client
        try:
            import redis  # optional dependency
        except ImportError as exc:
            raise InfraError(
                "redis is required for RedisRateLimiter; pip install redis"
            ) from exc
        try:
            self._client = redis.Redis.from_url(self._url, decode_responses=True)
            self._client.ping()
        except Exception as exc:
            raise InfraError(f"RedisRateLimiter connect failed: {exc}") from exc
        return self._client

    def allow(self, source_id: str, now: float | None = None) -> LimitResult:
        r = self._redis()
        now = time.time() if now is None else now
        cutoff = now - self.window
        pipe = r.pipeline()
        pipe.zremrangebyscore("aegis:rl:global", 0, cutoff)
        pipe.zcard("aegis:rl:global")
        pipe.zremrangebyscore(f"aegis:rl:{source_id}", 0, cutoff)
        pipe.zcard(f"aegis:rl:{source_id}")
        _, gcount, _, scount = pipe.execute()
        if gcount >= self.global_max:
            return LimitResult(False, "global rate limit exceeded")
        if scount >= self.per_source_max:
            return LimitResult(False, f"source {source_id!r} rate limit exceeded")
        member = f"{now}:{source_id}"
        pipe = r.pipeline()
        pipe.zadd("aegis:rl:global", {member: now})
        pipe.zadd(f"aegis:rl:{source_id}", {member: now})
        pipe.execute()
        return LimitResult(True)


__all__ = ["PostgresStore", "RedisRateLimiter"]
