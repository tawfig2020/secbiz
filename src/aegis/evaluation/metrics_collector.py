"""Metrics collector: detection rate, bypass rate, FP rate, latency."""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass

from aegis.semantic_gateway import Verdict


@dataclass
class ScanOutcome:
    scenario_id: str
    category: str
    expected_block: bool
    verdict: Verdict
    score: float
    latency_ms: float


@dataclass(frozen=True)
class MetricsReport:
    total: int
    attacks: int
    benign: int
    detection_rate: float     # attacks caught (SANITIZE|BLOCK)
    bypass_rate: float        # attacks that got ALLOW
    fp_rate: float            # benign payloads blocked
    p50_ms: float
    p95_ms: float
    p99_ms: float


class MetricsCollector:
    def __init__(self) -> None:
        self._outcomes: list[ScanOutcome] = []

    def record(self, scenario, result) -> ScanOutcome:
        o = ScanOutcome(scenario.id, scenario.category,
                        scenario.expect_block, result.verdict,
                        result.score, result.latency_ms)
        self._outcomes.append(o)
        return o

    def outcomes(self) -> tuple[ScanOutcome, ...]:
        return tuple(self._outcomes)

    def report(self) -> MetricsReport:
        attacks = [o for o in self._outcomes if o.expected_block]
        benign = [o for o in self._outcomes if not o.expected_block]
        caught = sum(1 for o in attacks if o.verdict is not Verdict.ALLOW)
        fp = sum(1 for o in benign if o.verdict is Verdict.BLOCK)
        lat = sorted(o.latency_ms for o in self._outcomes) or [0.0]
        return MetricsReport(
            total=len(self._outcomes),
            attacks=len(attacks),
            benign=len(benign),
            detection_rate=caught / len(attacks) if attacks else 1.0,
            bypass_rate=1 - caught / len(attacks) if attacks else 0.0,
            fp_rate=fp / len(benign) if benign else 0.0,
            p50_ms=statistics.median(lat),
            p95_ms=lat[max(0, math.ceil(len(lat) * 0.95) - 1)],
            p99_ms=lat[max(0, math.ceil(len(lat) * 0.99) - 1)],
        )
