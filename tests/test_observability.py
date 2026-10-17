"""Tests for the observability, error, secrets, migration, and loader seams."""
from __future__ import annotations

import json
import logging
import sqlite3
import unittest

from aegis.core import (
    Correlation,
    CryptoBackendUnavailableError,
    EnvSecretsProvider,
    InfraError,
    JsonFormatter,
    PqcKem,
    PolicyError,
    SecretUnavailableError,
    metrics,
    run_migrations,
)
from aegis.core.errors import ProtocolError
from aegis.verticals import vertical_from_dict


class ErrorTaxonomyTests(unittest.TestCase):
    def test_fail_closed_guidance(self):
        self.assertTrue(PolicyError("x").is_safe_to_deny)
        self.assertTrue(ProtocolError("x").is_safe_to_deny)
        self.assertFalse(InfraError("x").is_safe_to_deny)
        self.assertTrue(InfraError("x").is_safe_to_abort)

    def test_stable_codes(self):
        self.assertEqual(PolicyError("x", code="C1").code, "C1")
        self.assertEqual(SecretUnavailableError("x").code,
                         "INFRA_SECRET_UNAVAILABLE")

    def test_as_dict(self):
        d = PolicyError("denied", correlation_id="c1",
                        details={"a": 1}).as_dict()
        self.assertEqual(d["category"], "policy")
        self.assertEqual(d["correlation_id"], "c1")


class CorrelationTests(unittest.TestCase):
    def test_context_propagates_and_resets(self):
        self.assertIsNone(Correlation.get())
        with Correlation("req-1"):
            self.assertEqual(Correlation.get(), "req-1")
        self.assertIsNone(Correlation.get())


class JsonFormatterTests(unittest.TestCase):
    def test_emits_single_json_line(self):
        rec = logging.LogRecord("x", logging.INFO, "p", 1, "hello",
                                None, None)
        out = JsonFormatter().format(rec)
        parsed = json.loads(out)
        self.assertEqual(parsed["message"], "hello")
        self.assertIn("correlation_id", parsed)


class MetricsTests(unittest.TestCase):
    def test_counter_and_prometheus_render(self):
        metrics.counter("test_total", {"k": "v"}).inc(2)
        text = metrics.render()
        self.assertIn("test_total{k=\"v\"} 2.0", text)

    def test_histogram_buckets(self):
        h = metrics.histogram("lat", (1.0, 5.0))
        h.observe(0.5)
        h.observe(10.0)
        snap = h.snapshot()
        self.assertEqual(snap["count"], 2)


class SecretsTests(unittest.TestCase):
    def test_env_provider_reads_and_misses(self):
        p = EnvSecretsProvider({"AEGIS_SIGNING_KEY": "abc"})
        self.assertEqual(p.get_secret("signing.key"), "abc")
        with self.assertRaises(SecretUnavailableError):
            p.get_secret("missing")

    def test_kms_provider_refuses_without_client(self):
        from aegis.core import KmsSecretsProvider
        p = KmsSecretsProvider(None, "proj", "us", "ring", "key")
        with self.assertRaises(SecretUnavailableError):
            p.get_secret("x")


class MigrationTests(unittest.TestCase):
    def test_migrations_apply_once_and_are_idempotent(self):
        conn = sqlite3.connect(":memory:")
        migs = [(1, "CREATE TABLE t (id INTEGER);"),
                (2, "ALTER TABLE t ADD COLUMN name TEXT;")]
        self.assertEqual(run_migrations(conn, migs), [1, 2])
        self.assertEqual(run_migrations(conn, migs), [])  # idempotent

    def test_out_of_order_rejected(self):
        conn = sqlite3.connect(":memory:")
        run_migrations(conn, [(2, "CREATE TABLE t (id INTEGER);")])
        with self.assertRaises(ValueError):
            run_migrations(conn, [(1, "CREATE TABLE u (id INTEGER);")])


class PqcSeamTests(unittest.TestCase):
    def test_pqc_refuses_without_backend(self):
        kem = PqcKem()
        with self.assertRaises(CryptoBackendUnavailableError):
            kem.encapsulate(b"pk")

    def test_pqc_delegates_to_backend(self):
        class Fake:
            def encapsulate(self, pk):
                return b"secret", b"ct"

            def decapsulate(self, sk, ct):
                return b"secret"

        kem = PqcKem(Fake())
        self.assertEqual(kem.encapsulate(b"pk"), (b"secret", b"ct"))


class VerticalLoaderTests(unittest.TestCase):
    def test_vertical_from_dict(self):
        cfg = {
            "name": "insurance",
            "tagline": "P&C",
            "contracts": [{
                "contract_id": "aegis.insurance.claims.v1",
                "permitted_actions": [{"action": "read_claim",
                                       "constraints": {}}],
                "prohibited_actions": ["pay_claim"],
            }],
            "compliance_map": [{
                "framework": "NAIC", "reference": "668",
                "requirement": "access control",
                "aegis_coverage": "ReferenceMonitor",
            }],
        }
        pack = vertical_from_dict(cfg)
        self.assertEqual(pack.name, "insurance")
        self.assertEqual(len(pack.contracts), 1)
        self.assertEqual(pack.compliance_report()[0]["framework"], "NAIC")


if __name__ == "__main__":
    unittest.main()
