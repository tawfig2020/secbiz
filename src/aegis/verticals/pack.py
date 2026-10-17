"""Verticalization: Core Platform + Verticalized Modules architecture.

The five pillars stay universal — the capability-bounded architecture and
cross-domain semantic firewall answer the same architectural problem in any
sector. A VerticalPack layers industry specialization on top:

  detectors        extra semantic-gateway detectors for the sector's attack
                   grammar (SWIFT messages, PHI identifiers, CUI markings)
  contracts        pre-built CapabilityContracts for sector workflows
                   (e.g. "SWIFT transfers always need dual approval")
  egress_pii /
  egress_secrets   extra EgressScanner patterns for regulated identifiers
  compliance_map   regulator-facing control mappings (DORA articles, HIPAA
                   safeguards, FedRAMP/NIST SP 800-53 families)
  latency budget   metadata.latency_budget_ms + latency_policy are
                   enforced by configure_gateway (fail_closed / degrade /
                   alert_only per sector)

`configure_gateway()` plugs the pack into a SemanticGateway in place;
`compliance_report()` renders the control map for audits and demo decks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..capability_bounded.capability_contract import CapabilityContract
from ..semantic_gateway.gateway import SemanticGateway
from ..semantic_gateway.latency import LatencyBudget, LatencyPolicy

PatternSpec = tuple[str, re.Pattern, float]   # (label, regex, severity)


@dataclass(frozen=True)
class ComplianceControl:
    framework: str                # "DORA", "HIPAA", "FedRAMP" ...
    reference: str                # "Art. 10", "164.312(e)", "SI-4" ...
    requirement: str              # what the regulator asks for
    aegis_coverage: str           # which component delivers it


@dataclass(frozen=True)
class VerticalPack:
    """Industry module installed on top of the core platform."""
    name: str
    tagline: str
    detectors: tuple[Callable[[], Any], ...] = ()   # detector factories
    contracts: tuple[CapabilityContract, ...] = ()
    egress_pii: tuple[PatternSpec, ...] = ()
    egress_secrets: tuple[PatternSpec, ...] = ()
    compliance_map: tuple[ComplianceControl, ...] = ()
    # Sector threat-intel: signature phrases bundled with the pack, plus
    # named feeds (FS-ISAC / H-ISAC / CISA) the deployment would poll.
    threat_signatures: tuple[str, ...] = ()
    intel_feeds: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # -- installation -----------------------------------------------------
    def configure_gateway(self, gateway: SemanticGateway) -> SemanticGateway:
        """Plug pack detectors and egress patterns into a gateway in place.
        Returns the same gateway for chaining."""
        for factory in self.detectors:
            det = factory()
            # Idempotent: re-installing a pack must not double-count a
            # detector (it would inflate fused scores).
            if not any(type(d) is type(det) for d in gateway.detectors):
                gateway.detectors.append(det)
        for label, pat, sev in self.egress_secrets:
            gateway.egress_scanner.add_secret(label, pat, sev)
        for label, pat, sev in self.egress_pii:
            gateway.egress_scanner.add_pii(label, pat, sev)
        self.apply_threat_intel(gateway)
        self.apply_latency_budget(gateway)
        return gateway

    def apply_latency_budget(self, gateway: SemanticGateway) -> None:
        """Enforce the declared latency_budget_ms (metadata was previously
        informational only). Policy comes from metadata.latency_policy:
        fail_closed | degrade_to_fast_path | alert_only."""
        budget_ms = self.metadata.get("latency_budget_ms")
        if budget_ms is None:
            return
        new = LatencyBudget(
            budget_ms=float(budget_ms),
            policy=LatencyPolicy(
                self.metadata.get("latency_policy", "alert_only")))
        current = gateway.latency_budget
        if current is not None:
            # Several verticals on one gateway: the STRICTEST wins. Last
            # writer must never silently weaken e.g. healthcare fail_closed.
            rank = {LatencyPolicy.ALERT_ONLY: 0,
                    LatencyPolicy.DEGRADE_TO_FAST_PATH: 1,
                    LatencyPolicy.FAIL_CLOSED: 2}
            new = LatencyBudget(
                budget_ms=min(current.budget_ms, new.budget_ms),
                policy=max(current.policy, new.policy, key=rank.__getitem__))
        gateway.latency_budget = new

    def apply_threat_intel(self, gateway: SemanticGateway) -> int:
        """Learn bundled sector signatures into the sequence detector
        (the same `learn_signature` hook HARD uses for self-evolved rules).
        Returns the number of signatures ingested."""
        seq = gateway.sequence_detector
        if seq is None or not self.threat_signatures:
            return 0
        for sig in self.threat_signatures:
            seq.learn_signature(sig, weight=0.8)
        if getattr(gateway, "_bus", None) is not None:
            try:
                gateway._bus.emit(
                    "intel", f"vertical_pack:{self.name}",
                    f"ingested {len(self.threat_signatures)} signatures",
                    feeds=list(self.intel_feeds) or [self.name],
                    signatures=list(self.threat_signatures))
            except Exception:
                pass
        return len(self.threat_signatures)

    def contract_registry(self) -> dict[str, CapabilityContract]:
        """contract_id -> contract, ready for ReferenceMonitor({}, audit)."""
        return {c.contract_id: c for c in self.contracts}

    def compliance_report(self) -> list[dict[str, str]]:
        """Regulator-facing rows: framework, citation, requirement, coverage."""
        return [
            {"framework": c.framework, "reference": c.reference,
             "requirement": c.requirement, "aegis_coverage": c.aegis_coverage}
            for c in self.compliance_map
        ]
