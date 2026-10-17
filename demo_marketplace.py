"""Marketplace walkthrough: catalog -> quote -> subscribe -> use.

Run: python demo_marketplace.py
"""
from __future__ import annotations

from aegis.plugins import (
    EnterpriseService,
    FakeKmsClient,
    InMemoryBilling,
    Marketplace,
    StarterService,
    StaticFeed,
    UsageMeter,
)


def main() -> None:
    market = Marketplace()

    print("=" * 64)
    print("  AEGIS MARKETPLACE — one core, many products")
    print("=" * 64)

    print("\n[1] CATALOG (base products per tier)")
    for product in market.catalog():
        print(f"    {product['id']:<12} ${product['total']:>6}/mo")

    print("\n[2] VERTICAL ADD-ONS")
    for name, price in market.addons().items():
        print(f"    {name:<12} +${price}/mo")

    print("\n[3] QUOTE — enterprise + bfsi + healthcare")
    print("   ", market.quote("enterprise", ("bfsi", "healthcare")))

    print("\n[4] SOLO (B2C self-serve)")
    solo = market.subscribe("solo")
    service = StarterService(solo.plugin, UsageMeter(billing=InMemoryBilling()))
    key = service.issue_key(email="founder@startup.dev")["api_key"]
    verdict = service.scan(key, "hello world")
    print(f"    scan 'hello world' -> {verdict.verdict}")
    print("    usage:", service.usage(key))

    print("\n[5] ENTERPRISE (B2B regulated)")
    kms = FakeKmsClient()
    feeds = StaticFeed({"FS-ISAC": ["redirect settlement to drop account"]})
    ent = EnterpriseService.onboard(
        market.registry, verticals=("bfsi",),
        kms_client=kms, feed_source=feeds)
    verdict = ent.evaluate_action(
        "execute_swift_message", "aegis.bfsi.transactions.v1")
    print(f"    evaluate 'execute_swift_message' -> {verdict.verdict}")
    print(f"    attestations: {ent.attestation_count()}")
    print(f"    merkle root : {ent.attestation_root()[:16]}...")
    print("    feed poll   :", ent.poll_feeds(("FS-ISAC",)))

    print("\nDone.")


if __name__ == "__main__":
    main()
