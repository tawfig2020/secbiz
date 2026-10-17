"""Chaos / failure-injection tests: prove fail-closed under partial failure."""
from __future__ import annotations

import unittest

from aegis.capability_bounded import Action, Context, ReferenceMonitor
from aegis.capability_bounded.capability_contract import CapabilityContract
from aegis.core import AuditLog
from aegis.semantic_gateway import SemanticGateway, Verdict


class _ExplodingDetector:
    name = "exploding"

    def scan(self, text, ctx):
        raise RuntimeError("simulated detector failure")


class GatewayChaosTests(unittest.TestCase):
    def test_detector_exception_fails_closed(self):
        gw = SemanticGateway(detectors=[_ExplodingDetector()])
        res = gw.scan("benign payload")
        self.assertIs(res.verdict, Verdict.BLOCK)

    def test_oversized_payload_fails_closed(self):
        gw = SemanticGateway(max_payload_bytes=16)
        res = gw.scan("x" * 100)
        self.assertIs(res.verdict, Verdict.BLOCK)


class MonitorChaosTests(unittest.TestCase):
    def test_unknown_contract_fails_closed(self):
        mon = ReferenceMonitor({}, AuditLog())
        res = mon.evaluate(Action("anything"), Context("missing.contract"))
        self.assertEqual(res.decision.value, "DENY")

    def test_unlisted_action_fails_closed(self):
        contract = CapabilityContract.from_dict({
            "contract_id": "c.v1",
            "permitted_actions": [{"action": "read", "constraints": {}}]})
        mon = ReferenceMonitor({"c.v1": contract}, AuditLog())
        res = mon.evaluate(Action("write"), Context("c.v1"))
        self.assertEqual(res.decision.value, "DENY")


if __name__ == "__main__":
    unittest.main()
