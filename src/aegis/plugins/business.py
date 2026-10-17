"""Business tier service (Phase 3): dashboard + HARD + managed onboarding.

The SME/Business tier adds observability and self-improvement on top of the
core containment surface. A BusinessService wraps a resolved plugin that
carries an EventBus, exposing:

  scan / evaluate_action   -> same containment surface as the core
  dashboard()              -> JSON-safe executive/SOC/threat-intel snapshot
  run_hard_cycle()         -> one HARD self-improvement cycle (tier-gated)
  compliance_report()      -> regulator control mappings for the tenant
  BusinessService.onboard() -> sales-assisted tenant provisioning
"""
from __future__ import annotations

from typing import Any, Mapping

from ..dashboard import (
    DashboardAggregator,
    EventBus,
    KIND_HARD,
    snapshot_dict,
)
from ..edge import ModuleVerdict
from ..self_improvement import HardFramework
from .manifest import PluginManifest
from .registry import PluginRegistry, ResolvedPlugin, TierViolation
from .tier import BUSINESS


class BusinessService:
    """Observability + self-improvement facade over a resolved plugin."""

    def __init__(self, plugin: ResolvedPlugin) -> None:
        if plugin.bus is None:
            raise ValueError(
                "BusinessService requires a plugin resolved with an EventBus")
        self.plugin = plugin
        self.bus = plugin.bus
        self.aggregator = DashboardAggregator(
            self.bus, compliance_rows=plugin.compliance_rows)
        self._hard = (HardFramework(plugin.gateway)
                      if plugin.tier.hard_self_improve else None)

    # -- containment surface ---------------------------------------------
    def scan(self, payload: str, source_id: str = "business") -> ModuleVerdict:
        return self.plugin.module.inspect_request(payload, source_id=source_id)

    def evaluate_action(self, action: str, contract_id: str,
                        params: Mapping[str, Any] | None = None) -> ModuleVerdict:
        return self.plugin.module.evaluate_action(action, contract_id, params)

    # -- observability ----------------------------------------------------
    def dashboard(self) -> dict[str, Any]:
        return snapshot_dict(self.aggregator.snapshot())

    def compliance_report(self) -> list[dict[str, Any]]:
        return list(self.plugin.compliance_rows)

    # -- self-improvement -------------------------------------------------
    def run_hard_cycle(self, max_signatures: int = 6) -> dict[str, Any]:
        if self._hard is None:
            raise TierViolation(
                f"tier {self.plugin.tier.id!r} does not include HARD "
                "self-improvement")
        report = self._hard.cycle(max_signatures=max_signatures)
        self.bus.emit(
            KIND_HARD, "business_service",
            f"HARD cycle {'accepted' if report.accepted else 'rejected'}",
            accepted=report.accepted, phase="complete",
            signatures=report.learned_signatures,
            contract_recommendations=report.contract_recommendations)
        return {
            "accepted": report.accepted,
            "bypass_before": report.bypass_before,
            "bypass_after": report.bypass_after,
            "generalization_gap": report.generalization_gap,
            "learned_signatures": report.learned_signatures,
            "contract_recommendations": report.contract_recommendations,
        }

    # -- managed onboarding ----------------------------------------------
    @classmethod
    def onboard(cls, registry: PluginRegistry,
                verticals: tuple[str, ...] = (),
                limits: Mapping[str, int] | None = None,
                bus: EventBus | None = None) -> "BusinessService":
        """Sales-assisted provisioning: resolve a BUSINESS plugin with an
        EventBus and return a ready service."""
        plugin = registry.resolve(
            PluginManifest(tier=BUSINESS, verticals=verticals,
                           limits=dict(limits or {})),
            event_bus=bus or EventBus())
        return cls(plugin)


__all__ = ["BusinessService"]
