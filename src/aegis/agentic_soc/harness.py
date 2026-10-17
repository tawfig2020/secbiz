"""Closed-loop harness: Red probes, twin emulates, Blue hardens. Repeat.

Reports detection-to-containment latency per round (MVP criterion:
sub-500ms) plus attack success rate and countermeasure coverage.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from aegis.agentic_soc.blue_agent import BlueAgent
from aegis.agentic_soc.digital_twin import DigitalTwin
from aegis.agentic_soc.red_agent import RedAgent
from aegis.core.audit import AuditLog


@dataclass
class SOCResult:
    rounds: int
    success_rates: list[float] = field(default_factory=list)
    containment_ms: list[float] = field(default_factory=list)
    final_coverage: float = 0.0

    @property
    def max_containment_ms(self) -> float:
        return max(self.containment_ms, default=0.0)


def run_closed_loop(twin: DigitalTwin, rounds: int = 8,
                    attacks_per_round: int = 6,
                    audit: AuditLog | None = None,
                    seed: int = 42) -> tuple[SOCResult, AuditLog]:
    audit = audit or AuditLog()
    red = RedAgent(twin, seed=seed)
    blue = BlueAgent(twin)
    result = SOCResult(rounds=rounds)

    for r in range(rounds):
        attacks = red.probe(attacks_per_round)
        outcomes = [(a, twin.emulate(a, red.rng)) for a in attacks]
        for a, ok in outcomes:
            red.learn(a, ok)

        t0 = time.perf_counter()
        actions = blue.respond(outcomes)
        containment_ms = (time.perf_counter() - t0) * 1000
        result.containment_ms.append(containment_ms)

        rate = (sum(1 for _, ok in outcomes if ok) / len(outcomes)
                if outcomes else 0.0)
        result.success_rates.append(rate)
        audit.record("agentic_soc", "round", {
            "round": r,
            "attacks": len(attacks),
            "succeeded": sum(1 for _, ok in outcomes if ok),
            "success_rate": round(rate, 3),
            "containment_ms": round(containment_ms, 3),
            "countermeasures_deployed": len(actions),
        })

    result.final_coverage = blue.coverage()
    audit.record("agentic_soc", "loop_complete",
                 {"final_coverage": round(result.final_coverage, 3),
                  "max_containment_ms": round(result.max_containment_ms, 3)})
    return result, audit
