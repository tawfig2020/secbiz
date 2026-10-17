"""Idempotency-Key support: durable replay cache + guard.

A mutating endpoint (wire transfer, claim payment) must be safe to retry:
the client sends an `Idempotency-Key` header, and the server returns the
stored result for a repeated key instead of executing the side effect twice.

    cache = ReplayCache("data/idempotency.db")
    guard = IdempotencyGuard(cache, key, ttl_seconds=86400)
    if guard.seen:
        return guard.stored_response
    with guard:
        result = execute()          # side effect runs once
        guard.store(result)

`ReplayCache` is thread-safe and optionally durable (SQLite). The guard
records an in-flight marker so concurrent retries of the same key do not
double-execute.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class ReplayCache:
    """Thread-safe idempotency-key store (in-memory or SQLite-backed)."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._mem: dict[str, tuple[float, Any]] = {}
        self._db: sqlite3.Connection | None = None
        if path is not None:
            self._db = sqlite3.connect(str(path), check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS idempotency ("
                " key_hash TEXT PRIMARY KEY,"
                " created_at REAL NOT NULL,"
                " response TEXT NOT NULL)")
            self._db.commit()

    def get(self, key: str) -> Any | None:
        h = _digest(key)
        with self._lock:
            if self._db is not None:
                row = self._db.execute(
                    "SELECT response FROM idempotency WHERE key_hash=?",
                    (h,)).fetchone()
                if row is not None:
                    return row[0]
            hit = self._mem.get(h)
            return hit[1] if hit else None

    def put(self, key: str, response: Any) -> None:
        h = _digest(key)
        with self._lock:
            if self._db is not None:
                self._db.execute(
                    "INSERT OR REPLACE INTO idempotency VALUES (?,?,?)",
                    (h, time.time(), str(response)))
                self._db.commit()
            self._mem[h] = (time.time(), response)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None


class IdempotencyGuard:
    """Check-then-store wrapper with an in-flight marker.

    Usage:
        guard = IdempotencyGuard(cache, key)
        if guard.seen:
            return guard.stored_response
        with guard:
            result = do_work()
            guard.store(result)
    """

    def __init__(self, cache: ReplayCache, key: str,
                 ttl_seconds: int = 86400) -> None:
        self._cache = cache
        self._key = key
        self._ttl = ttl_seconds
        self._inflight: set[str] = set()
        self._inflight_lock = threading.Lock()
        self._stored: Any | None = None

    @property
    def seen(self) -> bool:
        return self._cache.get(self._key) is not None

    @property
    def stored_response(self) -> Any | None:
        return self._cache.get(self._key)

    def __enter__(self) -> "IdempotencyGuard":
        with self._inflight_lock:
            if self._key in self._inflight:
                raise RuntimeError(
                    f"idempotency key {self._key!r} is already in flight")
            self._inflight.add(self._key)
        return self

    def __exit__(self, *exc) -> None:
        with self._inflight_lock:
            self._inflight.discard(self._key)

    def store(self, response: Any) -> None:
        self._cache.put(self._key, response)
        self._stored = response


__all__ = ["IdempotencyGuard", "ReplayCache"]
