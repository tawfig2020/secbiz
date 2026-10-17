"""Marketplace (Phase 5): catalog + per-vertical add-on pricing + checkout.

The distribution layer. A Product is a tier plus optional vertical add-ons;
the Marketplace prices it as base tier + sum of add-ons, lists the catalog,
and provisions a resolved plugin on subscribe. Real billing attaches behind
the BillingHook seam (Phase 2); these are the catalog's quoted list prices.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .manifest import PluginManifest
from .registry import PluginRegistry, ResolvedPlugin
from .tier import TIERS, Tier, get_tier

# Illustrative monthly list prices (USD).
TIER_BASE_PRICE: Mapping[str, int] = {
    "solo": 29,
    "business": 500,
    "enterprise": 5000,
    "regulated": 50000,
}

VERTICAL_ADDON_PRICE: Mapping[str, int] = {
    "bfsi": 200,
    "healthcare": 200,
    "government": 300,
}


@dataclass(frozen=True)
class Product:
    """A catalog listing: a tier plus optional vertical add-ons."""
    tier: Tier
    verticals: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        suffix = "-" + "+".join(self.verticals) if self.verticals else ""
        return f"{self.tier.id}{suffix}"


@dataclass
class Subscription:
    """A purchased product plus its provisioned, tier-gated plugin."""
    product: Product
    plugin: ResolvedPlugin
    price: int

    def summary(self) -> dict[str, Any]:
        return {
            **self.plugin.summary(),
            "product": self.product.id,
            "price": self.price,
        }


class Marketplace:
    """Catalog + pricing + checkout. Provisioning delegates to the registry."""

    def __init__(self, registry: PluginRegistry | None = None,
                 base_prices: Mapping[str, int] | None = None,
                 addon_prices: Mapping[str, int] | None = None) -> None:
        self.registry = registry or PluginRegistry()
        self._base = dict(base_prices or TIER_BASE_PRICE)
        self._addon = dict(addon_prices or VERTICAL_ADDON_PRICE)

    # -- catalog ----------------------------------------------------------
    def product(self, tier_id: str,
                verticals: tuple[str, ...] = ()) -> Product:
        if len(set(verticals)) != len(verticals):
            raise ValueError(f"duplicate verticals in {verticals!r}")
        unknown = [v for v in verticals if v not in self._addon]
        if unknown:
            raise KeyError(
                f"unknown vertical(s) {unknown}; priced: {sorted(self._addon)}")
        return Product(get_tier(tier_id), verticals)

    def price(self, product: Product) -> int:
        base = self._base.get(product.tier.id, 0)
        addons = sum(self._addon.get(v, 0) for v in product.verticals)
        return base + addons

    def quote(self, tier_id: str,
              verticals: tuple[str, ...] = ()) -> dict[str, Any]:
        product = self.product(tier_id, verticals)
        return {
            "id": product.id,
            "tier": product.tier.id,
            "base_price": self._base.get(product.tier.id, 0),
            "addons": {v: self._addon.get(v, 0) for v in product.verticals},
            "total": self.price(product),
        }

    def catalog(self) -> list[dict[str, Any]]:
        """Base products, one per tier."""
        return [self.quote(tier_id) for tier_id in TIERS]

    def addons(self) -> dict[str, int]:
        """Vertical add-on prices."""
        return dict(self._addon)

    # -- checkout ---------------------------------------------------------
    def subscribe(self, tier_id: str,
                  verticals: tuple[str, ...] = (),
                  limits: Mapping[str, int] | None = None,
                  **resolve_kwargs: Any) -> Subscription:
        """Provision a plugin for the purchased product."""
        product = self.product(tier_id, verticals)
        plugin = self.registry.resolve(
            PluginManifest(tier=product.tier, verticals=product.verticals,
                           limits=dict(limits or {})),
            **resolve_kwargs)
        return Subscription(product, plugin, self.price(product))


__all__ = [
    "Marketplace",
    "Product",
    "Subscription",
    "TIER_BASE_PRICE",
    "VERTICAL_ADDON_PRICE",
]
