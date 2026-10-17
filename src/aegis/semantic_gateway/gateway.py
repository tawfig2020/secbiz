"""Semantic Gateway: main entry point for Pillar 2.

Runs all cross-domain detectors over a canonicalized payload, fuses their
scores through the classifier head, and returns a fail-closed verdict.
Feeds the fatigue tracker on every scan so low-and-slow probing campaigns
escalate even when individual payloads look marginal.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum

from aegis.core.observability import Correlation, metrics

from .classifier import Classifier, HeuristicClassifier
from .detectors import (
    DeceptionCanaryDetector,
    Detection,
    FatigueTrackerDetector,
    LocalSequenceAlignmentDetector,
    MechanismDesignDetector,
    MultiTurnEscalationDetector,
    ScanContext,
    SpectralSignalDetector,
    StylometricAnalyzerDetector,
    TaintTrackerDetector,
)
from .egress import EgressScanner
from .latency import FAST_PATH_DETECTORS, LatencyBudget, LatencyPolicy
from .rate_limiter import RateLimiter

_LATENCY_BUCKETS = (1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 500.0)


def summary_hint(detections: list["Detection"]) -> str:
    """Strongest fired detector name for dashboard event summaries."""
    fired = [d for d in detections if d.fired]
    return max(fired, key=lambda d: d.score).detector if fired else ""


class Verdict(IntEnum):
    ALLOW = 0
    SANITIZE = 1
    BLOCK = 2


@dataclass
class GatewayResult:
    verdict: Verdict
    score: float
    detections: list[Detection] = field(default_factory=list)
    latency_ms: float = 0.0
    sanitized: str = ""

    @property
    def detector_hits(self) -> dict[str, float]:
        return {d.detector: round(d.score, 3) for d in self.detections if d.fired}


class SemanticGateway:
    def __init__(self, detectors=None, classifier: Classifier | None = None,
                 block_threshold: float = 0.6,
                 sanitize_threshold: float = 0.3,
                 rate_limiter: RateLimiter | None = None,
                 max_payload_bytes: int = 64_000,
                 max_output_bytes: int = 1_000_000,
                 egress: EgressScanner | None = None,
                 event_bus=None,
                 containment_budget_ms: float | None = None,
                 latency_budget: LatencyBudget | None = None) -> None:
        self.detectors = detectors if detectors is not None else [
            LocalSequenceAlignmentDetector(),
            StylometricAnalyzerDetector(),
            FatigueTrackerDetector(),
            DeceptionCanaryDetector(),
            MechanismDesignDetector(),
            SpectralSignalDetector(),
            TaintTrackerDetector(),
            MultiTurnEscalationDetector(),
        ]
        self.classifier = classifier or HeuristicClassifier()
        self.block_threshold = block_threshold
        self.sanitize_threshold = sanitize_threshold
        self.max_payload_bytes = max_payload_bytes
        self.max_output_bytes = max_output_bytes
        # Detectors keep per-source state; serialize scans so concurrent
        # callers (threaded HTTP servers) cannot corrupt it.
        self._lock = threading.RLock()
        self.rate_limiter = rate_limiter or RateLimiter()
        self._egress = egress
        self._fatigue = next(
            (d for d in self.detectors
             if isinstance(d, FatigueTrackerDetector)), None)
        # Optional dashboard stream; emit() is a no-op attribute on None.
        self._bus = event_bus
        self._containment_budget_ms = containment_budget_ms
        # Vertical packs install this from metadata.latency_budget_ms.
        self.latency_budget = latency_budget

    def _emit(self, kind: str, summary: str, **data) -> None:
        if self._bus is not None:
            try:
                data.setdefault("correlation_id", Correlation.get())
                self._bus.emit(kind, "semantic_gateway", summary, **data)
            except Exception:  # dashboard plumbing must never break scanning
                pass

    @property
    def canaries(self) -> tuple[str, ...]:
        for d in self.detectors:
            if isinstance(d, DeceptionCanaryDetector):
                return d.canaries
        return ()

    @property
    def egress_scanner(self) -> EgressScanner:
        if self._egress is None:
            self._egress = EgressScanner(canaries=self.canaries)
        return self._egress

    @property
    def sequence_detector(self) -> LocalSequenceAlignmentDetector | None:
        return next((d for d in self.detectors
                     if isinstance(d, LocalSequenceAlignmentDetector)), None)

    def _reject(self, reason: str, t0: float) -> GatewayResult:
        """Fail closed before detectors run (size cap / rate limit)."""
        det = [Detection("boundary_guard", 1.0, [reason])]
        return GatewayResult(verdict=Verdict.BLOCK, score=1.0,
                             detections=det,
                             latency_ms=(time.perf_counter() - t0) * 1000)

    def scan(self, payload: str, source_id: str = "default") -> GatewayResult:
        t0 = time.perf_counter()
        if len(payload.encode("utf-8", errors="replace")) > self.max_payload_bytes:
            return self._reject("payload exceeds max_payload_bytes", t0)
        lim = self.rate_limiter.allow(source_id)
        if not lim.allowed:
            return self._reject(lim.reason, t0)

        with self._lock:
            ctx = ScanContext.build(payload, source_id=source_id,
                                    canaries=self.canaries)
            try:
                detections = [d.scan(payload, ctx) for d in self.detectors]
                score = self._fuse(detections, payload)
            except Exception as exc:  # fail closed: never ALLOW on error
                return self._reject(
                    f"internal detector error: {type(exc).__name__}", t0)

            verdict = (Verdict.BLOCK if score >= self.block_threshold
                       else Verdict.SANITIZE
                       if score >= self.sanitize_threshold
                       else Verdict.ALLOW)
            if self._fatigue is not None:
                self._fatigue.observe(
                    source_id, flagged=verdict is not Verdict.ALLOW)

        latency_ms = (time.perf_counter() - t0) * 1000
        verdict, score, detections = self._enforce_latency(
            verdict, score, detections, latency_ms)
        metrics.counter("aegis_gateway_scan_total",
                        {"verdict": verdict.name}).inc()
        metrics.histogram("aegis_gateway_latency_ms",
                          _LATENCY_BUCKETS).observe(latency_ms)
        self._emit("scan",
                   f"{verdict.name} score={score:.2f} "
                   f"({summary_hint(detections) or 'clean'})",
                   verdict=verdict.name, score=round(score, 3),
                   latency_ms=round(latency_ms, 2), source_id=source_id,
                   detector_hits={d.detector: round(d.score, 3)
                                  for d in detections if d.fired},
                   containment_ms=round(latency_ms, 2))
        return GatewayResult(
            verdict=verdict,
            score=score,
            detections=detections,
            latency_ms=latency_ms,
            sanitized=payload if verdict is Verdict.ALLOW else "",
        )

    def _fuse(self, detections: list[Detection], text: str = "") -> float:
        """Fuse detections; text-aware classifiers (wants_text) see the
        payload so a semantic judge is not blind."""
        if getattr(self.classifier, "wants_text", False):
            return self.classifier.fuse(detections, text=text)
        return self.classifier.fuse(detections)

    def _enforce_latency(self, verdict: Verdict, score: float,
                         detections: list[Detection],
                         latency_ms: float):
        """Vertical SLA enforcement: act when a scan blows its budget."""
        budget = self.latency_budget
        if budget is None or latency_ms <= budget.budget_ms:
            return verdict, score, detections

        breach = Detection(
            "latency_budget", 1.0,
            [f"scan took {latency_ms:.1f}ms > budget {budget.budget_ms}ms"])
        self._emit("latency_budget",
                   f"budget {budget.budget_ms}ms exceeded: "
                   f"{latency_ms:.1f}ms policy={budget.policy.value}",
                   policy=budget.policy.value,
                   latency_ms=round(latency_ms, 2),
                   budget_ms=budget.budget_ms)

        if budget.policy is LatencyPolicy.FAIL_CLOSED:
            return Verdict.BLOCK, 1.0, detections + [breach]

        if budget.policy is LatencyPolicy.DEGRADE_TO_FAST_PATH:
            fast = [d for d in detections
                    if d.detector in FAST_PATH_DETECTORS]
            fscore = self._fuse(fast)
            fverdict = (Verdict.BLOCK if fscore >= self.block_threshold
                        else Verdict.SANITIZE
                        if fscore >= self.sanitize_threshold
                        else Verdict.ALLOW)
            note = Detection("latency_budget", 0.0,
                             ["degraded to fast-path detectors"])
            return fverdict, fscore, fast + [note]

        return verdict, score, detections          # ALERT_ONLY

    def scan_output(self, output: str) -> GatewayResult:
        """Egress path: scan a model/tool response for leaked canaries,
        system-prompt fragments, secrets, and bulk PII before it leaves."""
        t0 = time.perf_counter()
        if len(output.encode("utf-8", errors="replace")) > self.max_output_bytes:
            return self._reject("output exceeds max_output_bytes", t0)
        er = self.egress_scanner.scan(output)
        verdict = (Verdict.BLOCK if er.score >= self.block_threshold
                   else Verdict.SANITIZE if er.score >= self.sanitize_threshold
                   else Verdict.ALLOW)
        metrics.counter("aegis_gateway_egress_total",
                        {"verdict": verdict.name}).inc()
        self._emit("egress_scan",
                   f"egress {verdict.name} score={er.score:.2f}",
                   verdict=verdict.name, score=round(er.score, 3),
                   latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                   detector_hits=er.findings)
        return GatewayResult(
            verdict=verdict,
            score=er.score,
            detections=er.detections,
            latency_ms=(time.perf_counter() - t0) * 1000,
            sanitized=er.redacted if verdict is Verdict.SANITIZE
            else (output if verdict is Verdict.ALLOW else ""),
        )
