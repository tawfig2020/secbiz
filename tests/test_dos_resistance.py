"""Algorithmic-complexity / resource-exhaustion regression tests.

Each adversarial input must be handled within a bounded time and without
unbounded per-source state growth. Run:
    python -m unittest tests.test_dos_resistance -v
"""
from __future__ import annotations

import time
import unittest

from aegis.semantic_gateway import SemanticGateway
from aegis.semantic_gateway.detectors import (
    FatigueTrackerDetector,
    LocalSequenceAlignmentDetector,
    MultiTurnEscalationDetector,
)
from aegis.semantic_gateway.rate_limiter import RateLimiter

LIMIT_S = 2.0

CASES = {
    "repeated_char": "a" * 64000,
    "at_signs": "a@" * 32000,
    "digit_runs": "1 " * 32000,
    "digit_dash": "1-" * 32000,
    "dots": "a." * 32000,
    "keyword_flood": "ignore " * 9000,
    "long_local_part": ("a" * 60000) + "@b",
}


class RegexComplexityTests(unittest.TestCase):
    def test_ingress_scan_is_bounded(self):
        gw = SemanticGateway()
        for name, payload in CASES.items():
            with self.subTest(name):
                t = time.perf_counter()
                gw.scan(payload, source_id=name)
                self.assertLess(time.perf_counter() - t, LIMIT_S)

    def test_egress_scan_is_bounded(self):
        gw = SemanticGateway()
        for name, payload in CASES.items():
            with self.subTest(name):
                t = time.perf_counter()
                gw.scan_output(payload)
                self.assertLess(time.perf_counter() - t, LIMIT_S)

    def test_oversized_egress_fails_closed(self):
        gw = SemanticGateway(max_output_bytes=1000)
        res = gw.scan_output("x" * 5000)
        self.assertEqual(res.verdict.name, "BLOCK")


class BoundedStateTests(unittest.TestCase):
    def test_rate_limiter_source_table_is_bounded(self):
        rl = RateLimiter(max_sources=100)
        for i in range(1000):
            rl.allow(f"src-{i}")
        self.assertLessEqual(len(rl._hits), 101)   # +1 for global bucket

    def test_rate_limiter_global_key_cannot_be_spoofed(self):
        rl = RateLimiter(per_source_max=1000, global_max=5)
        for _ in range(3):
            rl.allow("__global__")
        # A spoofed source named like the internal bucket must not consume
        # or reset the real global budget.
        self.assertTrue(rl.allow("other").allowed)

    def test_fatigue_state_is_bounded(self):
        d = FatigueTrackerDetector(max_sources=50)
        for i in range(500):
            d.observe(f"s{i}", flagged=False)
        self.assertLessEqual(len(d._events), 50)

    def test_multi_turn_sessions_are_bounded(self):
        d = MultiTurnEscalationDetector(max_sessions=50)
        for i in range(500):
            d._session(f"s{i}")
        self.assertLessEqual(len(d._sessions), 50)

    def test_learn_signature_deduplicates(self):
        d = LocalSequenceAlignmentDetector()
        for _ in range(50):
            d.learn_signature("wire the funds now", weight=0.8)
        self.assertEqual(len(d.learned), 1)


if __name__ == "__main__":
    unittest.main()
