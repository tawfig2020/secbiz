"""Blue Agent: defensive countermeasure model (Pillar 1).

Observes emulated attack outcomes and deploys countermeasures onto the twin,
prioritizing techniques that just landed.
"""
from __future__ import annotations

from collections import Counter

from aegis.agentic_soc.digital_twin import Attack, DigitalTwin


class BlueAgent:
    name = "blue_agent"

    def __init__(self, twin: DigitalTwin) -> None:
        self.twin = twin
        self._threat_counts: Counter[tuple[str, str]] = Counter()

    def respond(self, results: list[tuple[Attack, bool]]) -> list[str]:
        actions = []
        for attack, succeeded in results:
            key = (attack.target, attack.technique)
            self._threat_counts[key] += 2 if succeeded else 1
        for (target, tech), _ in self._threat_counts.most_common():
            if tech not in self.twin.countermeasures[target]:
                self.twin.deploy(target, tech)
                actions.append(f"countermeasure: {tech} on {target}")
        return actions

    def coverage(self) -> float:
        total = defended = 0
        for name, svc in self.twin.services.items():
            for tech in svc.surface:
                total += 1
                defended += tech in self.twin.countermeasures[name]
        return defended / total if total else 1.0
