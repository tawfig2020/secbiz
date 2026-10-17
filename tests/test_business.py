"""Business tier service tests. Run: python -m unittest tests.test_business -v"""
from __future__ import annotations

import unittest

from aegis.capability_bounded import Action, Context, Decision
from aegis.dashboard import EventBus
from aegis.plugins import (
    BUSINESS,
    SOLO,
    BusinessService,
    PluginManifest,
    PluginRegistry,
    TierViolation,
)


class BusinessServiceTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry()

    def test_onboard_resolves_business_with_bus(self):
        service = BusinessService.onboard(self.registry, verticals=("bfsi",))
        self.assertEqual(service.plugin.tier, BUSINESS)
        self.assertIsNotNone(service.plugin.bus)

    def test_requires_event_bus(self):
        plugin = self.registry.resolve(PluginManifest(tier=BUSINESS))
        with self.assertRaises(ValueError):
            BusinessService(plugin)

    def test_scan_flows_to_dashboard(self):
        service = BusinessService.onboard(self.registry, verticals=("bfsi",))
        verdict = service.scan("confirm MT103 status for today")
        self.assertEqual(verdict.verdict, "ALLOW")
        snapshot = service.dashboard()
        self.assertGreaterEqual(snapshot["posture"]["scans_total"], 1)

    def test_evaluate_action_enforces_vertical_contract(self):
        service = BusinessService.onboard(self.registry, verticals=("bfsi",))
        verdict = service.evaluate_action(
            "wire_transfer", "aegis.bfsi.transactions.v1",
            {"amount": 100, "currency": "USD"})
        self.assertEqual(verdict.verdict, "DEFER_HUMAN")

    def test_compliance_report_from_vertical(self):
        service = BusinessService.onboard(self.registry, verticals=("bfsi",))
        rows = service.compliance_report()
        self.assertTrue(rows)
        self.assertIn("DORA", {r["framework"] for r in rows})

    def test_run_hard_cycle_returns_report(self):
        service = BusinessService.onboard(self.registry, verticals=("bfsi",))
        report = service.run_hard_cycle(max_signatures=2)
        for key in ("accepted", "bypass_before", "bypass_after",
                    "generalization_gap", "learned_signatures",
                    "contract_recommendations"):
            self.assertIn(key, report)

    def test_hard_cycle_gated_off_for_solo(self):
        plugin = self.registry.resolve(
            PluginManifest(tier=SOLO), event_bus=EventBus())
        service = BusinessService(plugin)
        with self.assertRaises(TierViolation):
            service.run_hard_cycle()


if __name__ == "__main__":
    unittest.main()
