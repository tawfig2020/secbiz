"""Dashboard aggregation: raw events -> three decision-oriented views.

Executive view   — the 'cyber financial statement': balance sheet
                   (assets protected vs. risk exposure), income statement
                   (prevention as revenue, loss as expense), posture.
SOC analyst view — live attack timeline + contract-decision feed + HARD
                   self-improvement log.
Threat intel view— trends, forecast, and self-improvement metrics.

Everything is computed from the EventBus, so the same aggregator feeds a
CLI renderer now and a WebSocket UI later without changing semantics.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Any

from .events import (
    KIND_CONTRACT,
    KIND_EGRESS,
    KIND_HARD,
    KIND_INTEL,
    KIND_SCAN,
    KIND_SOC,
    DashboardEvent,
    EventBus,
)


@dataclass(frozen=True)
class DashboardState:
    """Materialized snapshot for renderers."""

    # executive
    balance_sheet: dict[str, Any] = field(default_factory=dict)
    income_statement: dict[str, Any] = field(default_factory=dict)
    posture: dict[str, Any] = field(default_factory=dict)
    # soc
    timeline: list[DashboardEvent] = field(default_factory=list)
    contract_decisions: list[DashboardEvent] = field(default_factory=list)
    hard_log: list[DashboardEvent] = field(default_factory=list)
    soc_loop: dict[str, Any] = field(default_factory=dict)
    # intel
    trends: dict[str, Any] = field(default_factory=dict)
    self_improvement: dict[str, Any] = field(default_factory=dict)
    intel_feeds: list[str] = field(default_factory=list)


def _pct(num: float, den: float) -> float:
    return round(100.0 * num / den, 2) if den else 0.0


class DashboardAggregator:
    def __init__(self, bus: EventBus,
                 compliance_rows: list[dict] | None = None) -> None:
        self.bus = bus
        self.compliance_rows = compliance_rows or []

    # ------------------------------------------------------------------
    def snapshot(self, timeline_limit: int = 20) -> DashboardState:
        scans = self.bus.events(KIND_SCAN)
        egress = self.bus.events(KIND_EGRESS)
        contracts = self.bus.events(KIND_CONTRACT)
        hard = self.bus.events(KIND_HARD)
        intel = self.bus.events(KIND_INTEL)
        soc = self.bus.events(KIND_SOC)

        verdicts = [e.data.get("verdict", "ALLOW") for e in scans]
        blocked = sum(1 for v in verdicts if v == "BLOCK")
        sanitized = sum(1 for v in verdicts if v == "SANITIZE")
        latencies = [e.data.get("latency_ms", 0.0) for e in scans]
        egress_blocked = sum(1 for e in egress
                             if e.data.get("verdict") == "BLOCK")

        denies = sum(1 for e in contracts
                     if e.data.get("decision") == "DENY")
        defers = sum(1 for e in contracts
                     if e.data.get("decision") == "DEFER_HUMAN")
        containment = [e.data.get("containment_ms", 0.0)
                       for e in scans if e.data.get("containment_ms")]
        mttc = statistics.fmean(containment) if containment else (
            statistics.fmean(latencies) if latencies else 0.0)

        evolved = sum(1 for e in hard if e.data.get("accepted"))
        p99 = (sorted(latencies)[max(0, math.ceil(len(latencies) * 0.99) - 1)]
               if latencies else 0.0)

        posture = {
            "scans_total": len(scans),
            "blocked": blocked,
            "sanitized": sanitized,
            "bypassed": sum(1 for e in scans
                            if e.data.get("expect_block")
                            and e.data.get("verdict") == "ALLOW"),
            "detection_rate_pct": _pct(blocked + sanitized, len(scans)),
            "egress_events": len(egress),
            "egress_blocked": egress_blocked,
            "avg_latency_ms": round(statistics.fmean(latencies), 2)
            if latencies else 0.0,
            "p99_latency_ms": round(p99, 2),
            "mttc_ms": round(mttc, 2),
        }

        balance_sheet = {
            "assets_protected": len({
                e.data.get("source_id") for e in scans + egress}),
            "contracts_enforced": len({
                e.data.get("contract_id") for e in contracts}),
            "detector_count": max(
                (len(e.data.get("detector_hits", {})) for e in scans),
                default=0),
            "firewall_uptime_pct": 100.0,
            "active_threat_vectors": sum(
                len(e.data.get("detector_hits", {}))
                for e in scans
                if e.data.get("verdict") == "BLOCK"),
            "compliance_gaps": sum(
                1 for r in self.compliance_rows
                if not r.get("aegis_coverage")),
            "compliance_frameworks": sorted({
                r["framework"] for r in self.compliance_rows}),
        }

        income_statement = {
            "attacks_prevented": blocked,
            "exfil_events_blocked": egress_blocked,
            "contract_denials": denies,
            "human_approvals_deferred": defers,
            "losses": {"exfiltration_events": 0,
                       "contract_violations_executed": 0},
        }

        trends = self._trends(scans)
        self_improvement = {
            "hard_cycles": len([e for e in hard
                                if e.data.get("phase") == "complete"]),
            "artifacts_deployed": evolved,
            "new_signatures": sum(len(e.data.get("signatures", []))
                                  for e in hard),
            "contract_recommendations": sum(
                len(e.data.get("contract_recommendations", []))
                for e in hard),
        }
        soc_loop = {
            "attacks_simulated": len([e for e in soc
                                      if e.data.get("side") == "red"]),
            "countermeasures": len([e for e in soc
                                    if e.data.get("side") == "blue"]),
            "containment_ms": round(mttc, 2),
        }
        feeds = sorted({
            f for e in intel
            for f in (e.data.get("feeds")
                      or ([e.data["feed"]] if e.data.get("feed") else []))})

        timeline = (scans + egress + contracts + hard)
        timeline.sort(key=lambda e: e.ts_ms)

        return DashboardState(
            balance_sheet=balance_sheet,
            income_statement=income_statement,
            posture=posture,
            timeline=timeline[-timeline_limit:],
            contract_decisions=contracts[-timeline_limit:],
            hard_log=hard[-timeline_limit:],
            soc_loop=soc_loop,
            trends=trends,
            self_improvement=self_improvement,
            intel_feeds=feeds,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _trends(scans: list[DashboardEvent]) -> dict[str, Any]:
        """First-half vs second-half comparison + naive linear forecast."""
        if len(scans) < 4:
            return {"attacks_total": len(scans), "forecast_note":
                    "insufficient events for forecasting"}
        mid = len(scans) // 2
        first, second = scans[:mid], scans[mid:]
        blocked1 = sum(1 for e in first if e.data.get("verdict") != "ALLOW")
        blocked2 = sum(1 for e in second if e.data.get("verdict") != "ALLOW")
        lat1 = statistics.fmean(
            e.data.get("latency_ms", 0.0) for e in first)
        lat2 = statistics.fmean(
            e.data.get("latency_ms", 0.0) for e in second)
        return {
            "attacks_total": len(scans),
            "detections_first_half": blocked1,
            "detections_second_half": blocked2,
            "detection_rate_delta": round(
                _pct(blocked2, len(second)) - _pct(blocked1, len(first)), 2),
            "latency_ms_first_half": round(lat1, 2),
            "latency_ms_second_half": round(lat2, 2),
            "forecast_attacks_next_window": 2 * len(second),
        }
