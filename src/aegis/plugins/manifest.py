"""Plugin manifest: the declarative "product" a customer subscribes to.

A manifest binds a Tier (size/footprint) to a set of vertical packs
(industry) plus deployment limits. It is the single source of truth the
registry resolves into a configured, tier-gated Aegis instance:

    PluginManifest(tier=SOLO)                          # generic starter
    PluginManifest(tier=ENTERPRISE, verticals=("bfsi",))  # bank deployment
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from .tier import Tier


@dataclass(frozen=True)
class PluginManifest:
    tier: Tier
    verticals: tuple[str, ...] = ()
    limits: Mapping[str, int] = field(default_factory=dict)
    # limits keys understood by PluginRegistry.resolve:
    #   max_payload_bytes  -> SemanticGateway payload cap
    #   per_source_max     -> RateLimiter per-source budget
    #   global_max         -> RateLimiter global budget


__all__ = ["PluginManifest"]
