"""Plugin layer tests. Run: python -m unittest tests.test_plugins -v"""
from __future__ import annotations

import unittest
from dataclasses import replace

from aegis.capability_bounded import Action, Context, Decision
from aegis.plugins import (
    BUSINESS,
    ENTERPRISE,
    REGULATED,
    SOLO,
    TIERS,
    PluginManifest,
    PluginRegistry,
    ResolvedPlugin,
    TierViolation,
    get_tier,
)


class TierTests(unittest.TestCase):
    def test_presets_are_registered(self):
        self.assertEqual(set(TIERS), {"solo", "business", "enterprise", "regulated"})
        self.assertEqual(get_tier("SOLO"), SOLO)
        self.assertEqual(get_tier("enterprise"), ENTERPRISE)

    def test_unknown_tier_raises(self):
        with self.assertRaises(KeyError):
            get_tier("nope")

    def test_capability_flags(self):
        self.assertFalse(SOLO.capabilities()["soc_loop"])
        self.assertFalse(SOLO.capabilities()["llm_judge"])
        self.assertTrue(ENTERPRISE.capabilities()["mtac"])
        self.assertTrue(REGULATED.capabilities()["qkd"])
        self.assertTrue(REGULATED.capabilities()["kms_signer"])

    def test_tier_ordering_by_footprint(self):
        # Higher tiers never remove a lower tier's capabilities.
        for cap in SOLO.capabilities():
            self.assertLessEqual(
                SOLO.capabilities()[cap], ENTERPRISE.capabilities()[cap])


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry()

    def test_solo_resolves_to_generic_contract(self):
        plugin = self.registry.resolve(PluginManifest(tier=SOLO))
        self.assertIsInstance(plugin, ResolvedPlugin)
        self.assertIn("aegis.generic.assistant.v1", plugin.contracts)

    def test_solo_generic_contract_enforcement(self):
        plugin = self.registry.resolve(PluginManifest(tier=SOLO))
        cid = "aegis.generic.assistant.v1"
        # prohibited -> DENY
        res = plugin.monitor.evaluate(Action("execute_payment", {}), Context(cid))
        self.assertEqual(res.decision, Decision.DENY)
        # human-gated -> DEFER_HUMAN
        res = plugin.monitor.evaluate(Action("send_email", {}), Context(cid))
        self.assertEqual(res.decision, Decision.DEFER_HUMAN)
        # permitted -> ALLOW
        res = plugin.monitor.evaluate(Action("read_document", {}), Context(cid))
        self.assertEqual(res.decision, Decision.ALLOW)

    def test_module_surface_is_wired(self):
        plugin = self.registry.resolve(PluginManifest(tier=SOLO))
        verdict = plugin.module.inspect_request("hello world")
        self.assertEqual(verdict.verdict, "ALLOW")

    def test_enterprise_loads_vertical_pack(self):
        plugin = self.registry.resolve(
            PluginManifest(tier=ENTERPRISE, verticals=("bfsi",)))
        self.assertIn("aegis.bfsi.transactions.v1", plugin.contracts)
        res = plugin.monitor.evaluate(
            Action("wire_transfer", {"amount": 100, "currency": "USD"}),
            Context("aegis.bfsi.transactions.v1"))
        self.assertEqual(res.decision, Decision.DEFER_HUMAN)

    def test_unknown_vertical_raises(self):
        with self.assertRaises(KeyError):
            self.registry.resolve(
                PluginManifest(tier=ENTERPRISE, verticals=("retail",)))

    def test_tier_contract_budget_fails_closed(self):
        tiny = replace(SOLO, max_contracts=1)
        with self.assertRaises(TierViolation):
            self.registry.resolve(
                PluginManifest(tier=tiny, verticals=("bfsi", "healthcare")))

    def test_truncate_verticals_drops_and_warns(self):
        tiny = replace(SOLO, max_contracts=1)
        plugin = self.registry.resolve(
            PluginManifest(tier=tiny, verticals=("bfsi", "healthcare")),
            truncate_verticals=True)
        self.assertEqual(plugin.verticals, ("bfsi",))
        self.assertTrue(any("healthcare" in w for w in plugin.warnings))

    def test_agents_registry_wired_from_tier(self):
        plugin = self.registry.resolve(PluginManifest(tier=SOLO))
        self.assertIsNotNone(plugin.agents)
        self.assertEqual(plugin.agents.max_agents, 1)

    def test_summary_reflects_tier(self):
        plugin = self.registry.resolve(
            PluginManifest(tier=ENTERPRISE, verticals=("bfsi",)))
        summary = plugin.summary()
        self.assertEqual(summary["tier"], "enterprise")
        self.assertEqual(summary["verticals"], ["bfsi"])
        self.assertTrue(summary["capabilities"]["mtac"])
        self.assertIsNone(summary["max_contracts"])


if __name__ == "__main__":
    unittest.main()
