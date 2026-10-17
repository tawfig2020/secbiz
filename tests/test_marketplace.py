"""Marketplace tests. Run: python -m unittest tests.test_marketplace -v"""
from __future__ import annotations

import unittest

from aegis.plugins import (
    Marketplace,
    PluginRegistry,
    Product,
    Subscription,
    get_tier,
)


class MarketplaceTests(unittest.TestCase):
    def setUp(self):
        self.market = Marketplace()

    def test_quote_base_tier(self):
        quote = self.market.quote("solo")
        self.assertEqual(quote["tier"], "solo")
        self.assertEqual(quote["base_price"], 29)
        self.assertEqual(quote["addons"], {})
        self.assertEqual(quote["total"], 29)

    def test_quote_with_addons(self):
        quote = self.market.quote("enterprise", ("bfsi", "healthcare"))
        self.assertEqual(quote["base_price"], 5000)
        self.assertEqual(quote["addons"], {"bfsi": 200, "healthcare": 200})
        self.assertEqual(quote["total"], 5400)

    def test_catalog_lists_all_tiers(self):
        catalog = self.market.catalog()
        self.assertEqual(len(catalog), 4)
        self.assertEqual({c["tier"] for c in catalog},
                         {"solo", "business", "enterprise", "regulated"})

    def test_addons_returns_prices(self):
        self.assertEqual(self.market.addons()["bfsi"], 200)

    def test_subscribe_provisions_plugin(self):
        sub = self.market.subscribe("solo")
        self.assertIsInstance(sub, Subscription)
        self.assertEqual(sub.price, 29)
        self.assertIn("aegis.generic.assistant.v1", sub.plugin.contracts)

    def test_subscribe_with_vertical(self):
        sub = self.market.subscribe("enterprise", ("bfsi",))
        self.assertIn("aegis.bfsi.transactions.v1", sub.plugin.contracts)
        self.assertEqual(sub.price, 5200)

    def test_subscription_summary(self):
        sub = self.market.subscribe("business", ("healthcare",))
        summary = sub.summary()
        self.assertEqual(summary["product"], "business-healthcare")
        self.assertEqual(summary["price"], 700)
        self.assertEqual(summary["tier"], "business")

    def test_custom_addon_prices_override(self):
        market = Marketplace(addon_prices={"bfsi": 999})
        self.assertEqual(market.quote("solo", ("bfsi",))["total"], 29 + 999)

    def test_product_id(self):
        product = Product(get_tier("enterprise"), ("bfsi", "healthcare"))
        self.assertEqual(product.id, "enterprise-bfsi+healthcare")


if __name__ == "__main__":
    unittest.main()
