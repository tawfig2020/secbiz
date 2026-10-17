"""Plugin registry: resolve a manifest into a tier-gated Aegis instance.

This is the entitlement layer (L2). It wires the existing core + vertical
packs + edge module behind a Tier, enforcing limits fail-closed:

    registry = PluginRegistry()
    plugin   = registry.resolve(PluginManifest(tier=SOLO))
    plugin.module.inspect_request("...")       # gateway scan
    plugin.module.evaluate_action("...", "...")  # contract decision

The same objects the core already produces (SemanticGateway,
ReferenceMonitor, AegisModule) are returned — features are simply toggled
off at lower tiers rather than forked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..capability_bounded.capability_contract import CapabilityContract
from ..capability_bounded.reference_monitor import ReferenceMonitor
from ..core import Signer
from ..core.audit import AuditLog
from ..dashboard import EventBus
from ..edge import AegisModule
from ..semantic_gateway.classifier import Classifier
from ..semantic_gateway.gateway import SemanticGateway
from ..semantic_gateway.rate_limiter import RateLimiter
from ..verticals import available_packs, load_pack
from .manifest import PluginManifest
from .orchestration import AgentRegistry
from .tier import Tier


class TierViolation(ValueError):
    """Raised when a manifest requests more than its tier permits."""


def generic_contract() -> CapabilityContract:
    """Minimal read-mostly contract for the solo/startup tier.

    Destructive or credential-touching actions are prohibited outright;
    side-effectful actions (send_email) require human approval.
    """
    return CapabilityContract.from_dict({
        "contract_id": "aegis.generic.assistant.v1",
        "permitted_actions": [
            {"action": "read_document", "constraints": {}},
            {"action": "summarize", "constraints": {}},
            {"action": "draft_reply", "constraints": {}},
            {"action": "send_email", "constraints": {
                "requires_human_approval": True}},
        ],
        "prohibited_actions": [
            "execute_payment", "delete_record", "export_all_data",
            "change_permissions", "access_credentials",
        ],
        "audit_requirements": {"log_every_action": True, "retention_days": 365},
    })


@dataclass
class ResolvedPlugin:
    """A configured, tier-gated Aegis instance."""
    tier: Tier
    gateway: SemanticGateway
    monitor: ReferenceMonitor
    module: AegisModule
    verticals: tuple[str, ...] = ()
    contracts: tuple[str, ...] = ()
    bus: EventBus | None = None
    compliance_rows: list[dict[str, Any]] = field(default_factory=list)
    agents: AgentRegistry | None = None
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """JSON-safe product summary for dashboards / billing / demos."""
        return {
            "tier": self.tier.id,
            "label": self.tier.label,
            "price_band": self.tier.price_band,
            "verticals": list(self.verticals),
            "contracts": list(self.contracts),
            "capabilities": dict(self.tier.capabilities()),
            "max_agents": self.tier.max_agents,
            "max_contracts": self.tier.max_contracts,
            "registered_agents": self.agents.count() if self.agents else 0,
            "warnings": list(self.warnings),
        }


class PluginRegistry:
    """Resolve PluginManifest -> ResolvedPlugin, enforcing tier limits."""

    def __init__(self, pack_loader: Callable[[str], Any] = load_pack) -> None:
        self._pack_loader = pack_loader

    def resolve(self, manifest: PluginManifest,
                 event_bus: EventBus | None = None,
                 classifier: Classifier | None = None,
                 signer: Signer | None = None,
                 truncate_verticals: bool = False) -> ResolvedPlugin:
        # -- validate verticals -------------------------------------------
        known = set(available_packs())
        for name in manifest.verticals:
            if name not in known:
                raise KeyError(
                    f"unknown vertical {name!r}; available: {sorted(known)}")

        packs = [self._pack_loader(name) for name in manifest.verticals]

        # -- enforce tier contract budget ---------------------------------
        warnings: list[str] = []
        if manifest.tier.max_contracts is not None:
            kept: list = []
            total = 0
            for pack in packs:
                n = len(pack.contracts)
                if total + n > manifest.tier.max_contracts:
                    if truncate_verticals:
                        warnings.append(
                            f"vertical {pack.name!r} dropped: contract budget "
                            f"{manifest.tier.max_contracts} exceeded")
                        continue
                    raise TierViolation(
                        f"tier {manifest.tier.id!r} allows up to "
                        f"{manifest.tier.max_contracts} contracts; manifest "
                        f"requests {total + n}")
                total += n
                kept.append(pack)
            packs = kept

        # -- build tier-gated gateway -------------------------------------
        gateway = SemanticGateway(
            rate_limiter=RateLimiter(
                per_source_max=manifest.limits.get("per_source_max", 120),
                global_max=manifest.limits.get("global_max", 5000)),
            max_payload_bytes=manifest.limits.get("max_payload_bytes", 64_000),
            event_bus=event_bus,
            classifier=classifier)

        # -- install vertical packs + collect contracts + compliance -------
        contracts: dict[str, CapabilityContract] = {}
        compliance_rows: list[dict[str, Any]] = []
        for pack in packs:
            pack.configure_gateway(gateway)
            contracts.update(pack.contract_registry())
            compliance_rows.extend(pack.compliance_report())
        if not contracts:
            gc = generic_contract()
            contracts[gc.contract_id] = gc

        monitor = ReferenceMonitor(contracts, AuditLog(), event_bus=event_bus,
                                    signer=signer)
        module = AegisModule(gateway, monitor)
        return ResolvedPlugin(
            tier=manifest.tier,
            gateway=gateway,
            monitor=monitor,
            module=module,
            verticals=tuple(p.name for p in packs),
            contracts=tuple(contracts),
            bus=event_bus,
            compliance_rows=compliance_rows,
            agents=AgentRegistry(manifest.tier.max_agents),
            warnings=warnings)


__all__ = [
    "PluginRegistry",
    "ResolvedPlugin",
    "TierViolation",
    "generic_contract",
]
