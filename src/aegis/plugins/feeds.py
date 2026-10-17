"""Threat-intel feed connectors (FS-ISAC / H-ISAC / CISA).

Enterprise/Regulated deployments poll named feeds and ingest new signatures
into the gateway's sequence detector — the same `learn_signature` hook HARD
and vertical packs use. `UrlFeed` fetches over stdlib urllib; `StaticFeed`
serves offline signatures for tests and demos.
"""
from __future__ import annotations

import json
from typing import Mapping, Protocol
from urllib import parse, request

from ..semantic_gateway.gateway import SemanticGateway


FEED_URLS: Mapping[str, str] = {
    "FS-ISAC": "https://feeds.fsisac.com/aegis/signatures.json",
    "H-ISAC": "https://feeds.h-isac.org/aegis/signatures.json",
    "CISA": "https://feeds.cisa.gov/aegis/signatures.json",
}


class FeedSource(Protocol):
    def fetch(self, feed: str) -> list[str]: ...


class StaticFeed:
    """Offline feed: returns a fixed signature list per feed name."""

    def __init__(self, signatures: Mapping[str, list[str]] | None = None) -> None:
        self._sigs = dict(signatures or {})

    def fetch(self, feed: str) -> list[str]:
        return list(self._sigs.get(feed, []))


class UrlFeed:
    """Fetch signatures from a JSON endpoint: {"signatures": [...]}."""

    def __init__(self, urls: Mapping[str, str] | None = None,
                 api_keys: Mapping[str, str] | None = None) -> None:
        self._urls = dict(urls or FEED_URLS)
        self._api_keys = dict(api_keys or {})

    def fetch(self, feed: str) -> list[str]:
        url = self._urls.get(feed)
        if url is None:
            raise KeyError(f"unknown feed {feed!r}")
        if parse.urlparse(url).scheme not in ("http", "https"):
            raise ValueError(f"feed {feed!r}: only http(s) URLs are allowed")
        headers = {}
        key = self._api_keys.get(feed)
        if key:
            headers["X-API-Key"] = key
        req = request.Request(url, headers=headers)
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return list(data.get("signatures", []))


class FeedConnector:
    """Poll named feeds and ingest signatures into a gateway."""

    def __init__(self, gateway: SemanticGateway,
                 source: FeedSource | None = None) -> None:
        self.gateway = gateway
        self.source = source or UrlFeed()

    def poll(self, feeds: tuple[str, ...]) -> dict[str, int]:
        """Ingest signatures from each feed; returns per-feed counts."""
        seq = self.gateway.sequence_detector
        counts: dict[str, int] = {}
        for feed in feeds:
            signatures = self.source.fetch(feed)
            if seq is not None:
                for sig in signatures:
                    seq.learn_signature(sig, weight=0.8)
            counts[feed] = len(signatures)
        return counts


__all__ = [
    "FEED_URLS",
    "FeedConnector",
    "FeedSource",
    "StaticFeed",
    "UrlFeed",
]
