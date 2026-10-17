"""Agent orchestration registry tests. Run: python -m unittest tests.test_orchestration -v"""
from __future__ import annotations

import unittest

from aegis.plugins import AgentLimitExceeded, AgentRegistry


class AgentRegistryTests(unittest.TestCase):
    def test_register_within_budget(self):
        reg = AgentRegistry(max_agents=2)
        reg.register("a1")
        reg.register("a2")
        self.assertEqual(reg.count(), 2)

    def test_register_exceeds_budget_fails_closed(self):
        reg = AgentRegistry(max_agents=1)
        reg.register("a1")
        with self.assertRaises(AgentLimitExceeded):
            reg.register("a2")

    def test_unlimited_when_no_cap(self):
        reg = AgentRegistry()
        for i in range(100):
            reg.register(f"a{i}")
        self.assertEqual(reg.count(), 100)

    def test_unregister_frees_slot(self):
        reg = AgentRegistry(max_agents=1)
        reg.register("a1")
        reg.unregister("a1")
        reg.register("a2")          # should not raise
        self.assertEqual(reg.count(), 1)


if __name__ == "__main__":
    unittest.main()
