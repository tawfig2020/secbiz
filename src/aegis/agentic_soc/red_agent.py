"""Red Agent: offensive emulation (Pillar 1).

Samples attacks from the twin's exposed surface and reweights toward
techniques that keep landing -- adversarial co-evolution, not a static
replay script. Sector patterns are baked into the twin surfaces (SWIFT
manipulation, PHI exfiltration, data poisoning).
"""
from __future__ import annotations

import random

from aegis.agentic_soc.digital_twin import Attack, DigitalTwin


class RedAgent:
    name = "red_agent"

    def __init__(self, twin: DigitalTwin, seed: int = 42) -> None:
        self.twin = twin
        self.rng = random.Random(seed)
        self._success_weight: dict[str, float] = {}

    def probe(self, n: int = 5) -> list[Attack]:
        attacks = []
        for _ in range(n):
            svc = self.rng.choice(list(self.twin.services.values()))
            tech = self._pick(svc.surface)
            attacks.append(Attack(tech, svc.name,
                                  credential_access=svc.credential_density > 0.8))
        return attacks

    def _pick(self, surface: tuple[str, ...]) -> str:
        weights = [1.0 + self._success_weight.get(t, 0.0) for t in surface]
        return self.rng.choices(surface, weights=weights, k=1)[0]

    def learn(self, attack: Attack, succeeded: bool) -> None:
        if succeeded:
            self._success_weight[attack.technique] = (
                self._success_weight.get(attack.technique, 0.0) + 0.5)
