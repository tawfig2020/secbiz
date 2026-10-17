"""Tests for the financial-grade seams: Money, idempotency, feature flags."""
from __future__ import annotations

import unittest
from decimal import Decimal

from aegis.capability_bounded.capability_contract import (
    CapabilityContract,
    validate,
)
from aegis.core import (
    FeatureFlags,
    IdempotencyGuard,
    Money,
    ReplayCache,
)


class MoneyTests(unittest.TestCase):
    def test_from_minor_and_to_minor_roundtrip(self):
        m = Money.from_minor(4500000, "USD")       # $45,000.00
        self.assertEqual(m.to_minor(), 4500000)
        self.assertEqual(str(m), "45000.00 USD")

    def test_parse_is_exact(self):
        m = Money.parse("4,500,000.00", "USD")
        self.assertEqual(m.amount, Decimal("4500000.00"))

    def test_no_float_arithmetic(self):
        a = Money.from_minor(10, "USD")
        b = Money.from_minor(20, "USD")
        self.assertEqual((a + b).to_minor(), 30)
        self.assertIsInstance((a + b).amount, Decimal)

    def test_currency_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            Money.from_minor(1, "USD") + Money.from_minor(1, "EUR")


class MoneyContractTests(unittest.TestCase):
    def test_money_bound_enforced_in_minor_units(self):
        contract = CapabilityContract.from_dict({
            "contract_id": "c.v1",
            "permitted_actions": [{
                "action": "wire_transfer",
                "constraints": {"max_amount_minor": 5_000_000,
                                "currency": ["USD", "EUR"]},
            }],
        })
        ok = validate(contract, "wire_transfer",
                      {"amount": Money.from_minor(4_500_000, "USD")})
        self.assertEqual(ok, [])
        bad = validate(contract, "wire_transfer",
                       {"amount": Money.from_minor(9_999_999, "USD")})
        self.assertTrue(bad)

    def test_money_currency_allowlist(self):
        contract = CapabilityContract.from_dict({
            "contract_id": "c.v1",
            "permitted_actions": [{
                "action": "wire_transfer",
                "constraints": {"currency": ["USD"]},
            }],
        })
        bad = validate(contract, "wire_transfer",
                       {"amount": Money.from_minor(1, "JPY")})
        self.assertTrue(bad)


class IdempotencyTests(unittest.TestCase):
    def test_replay_cache_returns_stored_response(self):
        cache = ReplayCache()
        cache.put("key-1", "done")
        self.assertEqual(cache.get("key-1"), "done")
        self.assertIsNone(cache.get("key-2"))

    def test_guard_prevents_double_execution(self):
        cache = ReplayCache()
        guard = IdempotencyGuard(cache, "k")
        self.assertFalse(guard.seen)
        with guard:
            guard.store("result")
        self.assertTrue(IdempotencyGuard(cache, "k").seen)

    def test_durable_replay_cache(self):
        import tempfile
        import os
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            cache = ReplayCache(path)
            cache.put("k", "v")
            cache.close()
            cache2 = ReplayCache(path)
            self.assertEqual(cache2.get("k"), "v")
            cache2.close()
        finally:
            os.remove(path)


class FeatureFlagsTests(unittest.TestCase):
    def test_defaults_and_overrides(self):
        f = FeatureFlags({"a": False}, {"a": True, "b": True})
        self.assertTrue(f.enabled("a"))
        self.assertTrue(f.enabled("b"))
        self.assertFalse(f.enabled("missing"))

    def test_set_and_snapshot(self):
        f = FeatureFlags()
        f.set("x", True)
        self.assertEqual(f.snapshot(), {"x": True})


if __name__ == "__main__":
    unittest.main()
