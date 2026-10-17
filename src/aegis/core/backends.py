"""Backend selection from environment (Risk B wiring).

The reference build is in-memory. Production sets these environment variables
to select shared durable backends; the factory functions return the right
implementation without changing call sites:

    AEGIS_REDIS_URL=redis://...      -> RedisRateLimiter
    AEGIS_POSTGRES_DSN=postgresql:// -> PostgresStore

If the variable is unset, the in-memory default is returned (or `None` for
the optional KV store). A configured backend that fails to connect raises
`InfraError` — it never silently falls back to in-memory state.
"""
from __future__ import annotations

import os

from aegis.core.stores import PostgresStore, RedisRateLimiter
from aegis.semantic_gateway.rate_limiter import RateLimiter


def rate_limiter_from_env() -> RateLimiter:
    """Return a Redis-backed limiter when configured, else in-memory."""
    url = os.environ.get("AEGIS_REDIS_URL")
    if url:
        return RedisRateLimiter(url)
    return RateLimiter()


def kv_store_from_env() -> PostgresStore | None:
    """Return a Postgres KV store when configured, else None."""
    dsn = os.environ.get("AEGIS_POSTGRES_DSN")
    if dsn:
        return PostgresStore(dsn)
    return None


__all__ = ["kv_store_from_env", "rate_limiter_from_env"]
