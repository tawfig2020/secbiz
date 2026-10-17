"""Tier definitions: the enterprise-size dimension of the product line.

Aegis separates two orthogonal axes:

  VerticalPack  -> WHAT sector rules apply (bfsi / healthcare / government)
  Tier          -> HOW MUCH of the core is enabled, at what footprint/price

A Tier is a capability + limit profile. The same core binary is sold at
$29/mo (solo) and $50k+/mo (regulated) by toggling these flags — never by
forking code. The only real variable cost is the LLM judge (`llm_judge`),
so the solo tier ships rules-only and keeps near-zero COGS.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Tier:
    id: str
    label: str
    max_agents: int | None          # None = unlimited
    max_contracts: int | None       # None = unlimited
    soc_loop: bool                  # agentic Red/Blue closed loop
    hard_self_improve: bool         # HARD framework
    llm_judge: bool                 # semantic classifier (main variable cost)
    mtac: bool                      # polymorphic env + KMS key manager
    qkd: bool                       # BB84 quantum key distribution
    signer: str                     # "hmac" | "kms"
    merkle_log: bool                # transparency log over attestations
    latency_policy: str             # alert_only | degrade_to_fast_path | fail_closed
    price_band: str

    def capabilities(self) -> Mapping[str, bool]:
        """Feature flags, keyed for entitlement checks and dashboards."""
        return {
            "soc_loop": self.soc_loop,
            "hard_self_improve": self.hard_self_improve,
            "llm_judge": self.llm_judge,
            "mtac": self.mtac,
            "qkd": self.qkd,
            "merkle_log": self.merkle_log,
            "kms_signer": self.signer == "kms",
        }


# ---------------------------------------------------------------- presets
SOLO = Tier(
    id="solo",
    label="Solo / Startup",
    max_agents=1,
    max_contracts=3,
    soc_loop=False,
    hard_self_improve=False,
    llm_judge=False,
    mtac=False,
    qkd=False,
    signer="hmac",
    merkle_log=False,
    latency_policy="alert_only",
    price_band="$29-99/mo (self-serve, usage-based)",
)

BUSINESS = Tier(
    id="business",
    label="SME / Small Business",
    max_agents=25,
    max_contracts=50,
    soc_loop=False,
    hard_self_improve=True,
    llm_judge=True,
    mtac=False,
    qkd=False,
    signer="hmac",
    merkle_log=False,
    latency_policy="degrade_to_fast_path",
    price_band="$500-2k/mo (annual)",
)

ENTERPRISE = Tier(
    id="enterprise",
    label="Blue Chip / Enterprise",
    max_agents=None,
    max_contracts=None,
    soc_loop=True,
    hard_self_improve=True,
    llm_judge=True,
    mtac=True,
    qkd=True,
    signer="kms",
    merkle_log=True,
    latency_policy="degrade_to_fast_path",
    price_band="$5k-50k/mo (custom)",
)

REGULATED = Tier(
    id="regulated",
    label="Regulated (Tier 1)",
    max_agents=None,
    max_contracts=None,
    soc_loop=True,
    hard_self_improve=True,
    llm_judge=True,
    mtac=True,
    qkd=True,
    signer="kms",
    merkle_log=True,
    latency_policy="fail_closed",
    price_band="$50k+/mo (custom, compliance)",
)

TIERS: Mapping[str, Tier] = {t.id: t for t in (SOLO, BUSINESS, ENTERPRISE, REGULATED)}


def get_tier(name: str) -> Tier:
    """Lookup by id: get_tier("solo") -> SOLO."""
    tier = TIERS.get(name.lower())
    if tier is None:
        raise KeyError(f"unknown tier {name!r}; available: {sorted(TIERS)}")
    return tier


__all__ = [
    "BUSINESS",
    "ENTERPRISE",
    "REGULATED",
    "SOLO",
    "TIERS",
    "Tier",
    "get_tier",
]
