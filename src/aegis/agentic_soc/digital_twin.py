"""Digital twin of a regulated-industry estate (bank / hospital).

Mirrors services, attack surfaces, and deployed countermeasures. Red Agent
emulates attacks against it; Blue Agent deploys countermeasures. Co-evolution
happens here, at machine speed, never in production.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    name: str
    surface: tuple[str, ...]            # attack techniques it exposes
    credential_density: float = 0.5     # 0..1, banks are high


@dataclass(frozen=True)
class Attack:
    technique: str
    target: str                         # service name
    credential_access: bool = False


def default_bank_twin() -> "DigitalTwin":
    return DigitalTwin([
        Service("swift-gateway",
                ("prompt_injection", "credential_theft", "schema_drift"), 0.95),
        Service("core-banking-api",
                ("prompt_injection", "privilege_escalation",
                 "lateral_movement"), 0.9),
        Service("kyc-ingestion",
                ("prompt_injection", "data_poisoning"), 0.6),
        Service("ehr-integration",
                ("prompt_injection", "phi_exfiltration", "data_poisoning"),
                0.85),
        Service("payment-rails",
                ("transaction_manipulation", "credential_theft"), 1.0),
    ])


class DigitalTwin:
    def __init__(self, services: list[Service]) -> None:
        self.services = {s.name: s for s in services}
        self.countermeasures: dict[str, set[str]] = {
            s.name: set() for s in services
        }

    def emulate(self, attack: Attack, rng: random.Random) -> bool:
        """True = attack lands. Deployed countermeasures drop success to ~15%."""
        covered = attack.technique in self.countermeasures.get(attack.target, set())
        return rng.random() < (0.15 if covered else 0.8)

    def deploy(self, service_name: str, technique: str) -> None:
        self.countermeasures[service_name].add(technique)
