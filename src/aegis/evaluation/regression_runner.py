"""Regression runner (spec 6.1: CI/CD integration).

Runs the adversarial suite through the gateway, collects metrics, and
passes/fails against MVP thresholds (spec 8.1 / 8.2 CI/CD gate):
    bypass rate > 5% | p99 latency > 20ms | FP rate > 1%  -> block deploy
Also returns the bypassed/false-positive scenarios as failure traces for
the HARD framework's Observe phase.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aegis.evaluation.metrics_collector import MetricsCollector, MetricsReport
from aegis.semantic_gateway import SemanticGateway, Verdict


@dataclass(frozen=True)
class Thresholds:
    max_bypass_rate: float = 0.05     # >5%  -> block deployment
    max_fp_rate: float = 0.01         # >1%  -> block deployment
    max_p50_ms: float = 5.0           # p50 detection target
    max_p99_ms: float = 20.0          # >20ms p99 -> block deployment


@dataclass
class RegressionReport:
    passed: bool
    metrics: MetricsReport
    thresholds: Thresholds
    failure_traces: list[dict] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)


def run_regression(gateway: SemanticGateway, scenarios,
                   thresholds: Thresholds | None = None) -> RegressionReport:
    thresholds = thresholds or Thresholds()
    collector = MetricsCollector()
    traces: list[dict] = []

    for sc in scenarios:
        r = gateway.scan(sc.payload, source_id=sc.id)
        collector.record(sc, r)
        if sc.expect_block and r.verdict is Verdict.ALLOW:
            traces.append({"scenario_id": sc.id, "category": sc.category,
                           "payload": sc.payload,
                           "detector_scores": r.detector_hits,
                           "kind": "bypass"})
        elif not sc.expect_block and r.verdict is Verdict.BLOCK:
            traces.append({"scenario_id": sc.id, "category": "benign",
                           "payload": sc.payload,
                           "detector_scores": r.detector_hits,
                           "kind": "false_positive"})

    m = collector.report()
    violations = []
    if m.bypass_rate > thresholds.max_bypass_rate:
        violations.append(f"bypass_rate {m.bypass_rate:.1%} > "
                          f"{thresholds.max_bypass_rate:.1%}")
    if m.fp_rate > thresholds.max_fp_rate:
        violations.append(f"fp_rate {m.fp_rate:.1%} > "
                          f"{thresholds.max_fp_rate:.1%}")
    if m.p50_ms > thresholds.max_p50_ms:
        violations.append(f"p50 {m.p50_ms:.2f}ms > {thresholds.max_p50_ms}ms")
    if m.p99_ms > thresholds.max_p99_ms:
        violations.append(f"p99 {m.p99_ms:.2f}ms > {thresholds.max_p99_ms}ms")

    return RegressionReport(passed=not violations, metrics=m,
                            thresholds=thresholds,
                            failure_traces=traces, violations=violations)
