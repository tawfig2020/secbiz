"""Tests for the shared durable store seams (Risk B).

These adapters raise `InfraError` when their optional driver is absent —
they must never silently fall back to in-memory state in production.
"""
from __future__ import annotations

import importlib.util
import os
import unittest

from aegis.core import (
    InfraError,
    PostgresStore,
    RedisRateLimiter,
    kv_store_from_env,
    rate_limiter_from_env,
)
from aegis.semantic_gateway.rate_limiter import RateLimiter


class PostgresStoreTests(unittest.TestCase):
    def test_missing_driver_fails_closed(self):
        if importlib.util.find_spec("psycopg2") is not None:
            self.skipTest("psycopg2 installed; cannot test missing-driver path")
        with self.assertRaises(InfraError):
            PostgresStore("postgresql://u:p@localhost/db").get("k")


class RedisRateLimiterTests(unittest.TestCase):
    def test_missing_driver_fails_closed(self):
        if importlib.util.find_spec("redis") is not None:
            self.skipTest("redis installed; cannot test missing-driver path")
        with self.assertRaises(InfraError):
            RedisRateLimiter("redis://localhost:6379/0").allow("src")


class BackendFactoryTests(unittest.TestCase):
    def test_rate_limiter_defaults_to_in_memory(self):
        os.environ.pop("AEGIS_REDIS_URL", None)
        self.assertIsInstance(rate_limiter_from_env(), RateLimiter)

    def test_kv_store_defaults_to_none(self):
        os.environ.pop("AEGIS_POSTGRES_DSN", None)
        self.assertIsNone(kv_store_from_env())


if __name__ == "__main__":
    unittest.main()
