"""Aegis plugin layer: core + Tier (size) x Vertical (industry) = product.

The five pillars stay universal. A PluginManifest binds a Tier (how much
of the core is enabled, at what price) to a set of vertical packs (what
sector rules apply). PluginRegistry.resolve() turns that manifest into a
configured, tier-gated SemanticGateway + ReferenceMonitor + AegisModule.

The self-serve layer (Phase 2) wraps a resolved Solo plugin with API-key
issuance, usage metering, and a billing hook for the B2C starter tier.
"""
from .business import BusinessService
from .enterprise import EnterpriseService
from .feeds import FEED_URLS, FeedConnector, FeedSource, StaticFeed, UrlFeed
from .kms import CloudKmsClient, FakeKmsClient, KmsClient, KmsSigner
from .manifest import PluginManifest
from .marketplace import (
    Marketplace,
    Product,
    Subscription,
    TIER_BASE_PRICE,
    VERTICAL_ADDON_PRICE,
)
from .metering import BillingHook, InMemoryBilling, UsageMeter, UsageRecord
from .orchestration import AgentLimitExceeded, AgentRegistry
from .registry import (
    PluginRegistry,
    ResolvedPlugin,
    TierViolation,
    generic_contract,
)
from .selfserve import StarterService, Tenant, make_handler, serve_http
from .tier import (
    BUSINESS,
    ENTERPRISE,
    REGULATED,
    SOLO,
    TIERS,
    Tier,
    get_tier,
)

__all__ = [
    "BUSINESS",
    "ENTERPRISE",
    "REGULATED",
    "SOLO",
    "TIERS",
    "Tier",
    "TierViolation",
    "AgentLimitExceeded",
    "AgentRegistry",
    "BusinessService",
    "CloudKmsClient",
    "EnterpriseService",
    "FEED_URLS",
    "FakeKmsClient",
    "FeedConnector",
    "FeedSource",
    "KmsClient",
    "KmsSigner",
    "Marketplace",
    "PluginManifest",
    "PluginRegistry",
    "Product",
    "ResolvedPlugin",
    "StaticFeed",
    "Subscription",
    "TIER_BASE_PRICE",
    "UrlFeed",
    "VERTICAL_ADDON_PRICE",
    "BillingHook",
    "InMemoryBilling",
    "UsageMeter",
    "UsageRecord",
    "StarterService",
    "Tenant",
    "generic_contract",
    "get_tier",
    "make_handler",
    "serve_http",
]
