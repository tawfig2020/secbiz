"""Setup / bootstrap: load config (placeholders) and build the full stack.

Run: python bootstrap.py

Reads config.json (or AEGIS_* env vars), builds the KMS client, feed source,
and semantic judge, then wires the Marketplace + EnterpriseService. Prints a
readiness report showing which placeholders still need real values.

No network calls are made here — this only wires the seams.
"""
from __future__ import annotations

import hashlib

from aegis.config import Settings, load_settings
from aegis.plugins import EnterpriseService, FakeKmsClient, Marketplace, UrlFeed
from aegis.plugins.kms import CloudKmsClient


def build_kms_client(settings: Settings, sdk_client=None):
    """Return a KmsClient. `fake` works locally; `gcp` needs the SDK client."""
    if settings.kms_provider == "fake":
        return FakeKmsClient()

    if sdk_client is None:
        def _pending(*_a, **_k):
            raise RuntimeError(
                "GCP KMS not provisioned: replace placeholders and inject "
                "the Cloud KMS SDK client")
        return CloudKmsClient(_pending, _pending)

    # Real Google Cloud KMS asymmetric sign/verify.
    def sign(payload: bytes) -> bytes:
        resp = sdk_client.asymmetric_sign(request={
            "name": settings.kms_key_version_resource,
            "digest": {"sha256": hashlib.sha256(payload).digest()}})
        return resp.signature

    def verify(payload: bytes, signature: bytes) -> bool:
        resp = sdk_client.asymmetric_verify(request={
            "name": settings.kms_key_version_resource,
            "digest": {"sha256": hashlib.sha256(payload).digest()},
            "signature": signature})
        return resp.verified

    return CloudKmsClient(sign, verify)


def build_feed_source(settings: Settings) -> UrlFeed:
    urls = {
        "FS-ISAC": settings.feed_fsisac_url,
        "H-ISAC": settings.feed_hisac_url,
        "CISA": settings.feed_cisa_url,
    }
    api_keys = {
        "FS-ISAC": settings.feed_fsisac_api_key,
        "H-ISAC": settings.feed_hisac_api_key,
        "CISA": settings.feed_cisa_api_key,
    }
    # A placeholder is not a credential: never transmit it.
    api_keys = {k: v for k, v in api_keys.items()
                if v and not v.startswith("REPLACE_ME")}
    return UrlFeed(urls, api_keys)


def build_gemini_client(settings: Settings, sdk_client=None):
    """Return a Gemini judge client, or None to use the heuristic head."""
    return sdk_client


def main() -> None:
    settings = load_settings("config.json")

    print("=" * 64)
    print("  AEGIS SETUP / BOOTSTRAP")
    print("=" * 64)

    print(f"\n[config] environment={settings.environment}, "
          f"kms_provider={settings.kms_provider}")

    placeholders = settings.placeholders()
    if placeholders:
        print("\n[placeholders] replace with real values next week:")
        for key, value in placeholders.items():
            print(f"  {key} = {value}")
    else:
        print("\n[placeholders] none — all values configured")

    kms = build_kms_client(settings)
    feeds = build_feed_source(settings)
    gemini = build_gemini_client(settings)

    market = Marketplace()
    ent = EnterpriseService.onboard(
        market.registry, verticals=("bfsi",),
        kms_client=kms, feed_source=feeds, gemini_client=gemini)

    print("\n[stack]")
    print(f"  KMS client     : {type(kms).__name__}")
    print(f"  feed source    : {type(feeds).__name__}")
    print(f"  semantic judge : "
          f"{'GeminiClassifier' if gemini else 'heuristic (fallback)'}")
    print(f"  enterprise     : {ent.plugin.tier.id} "
          f"+ {list(ent.plugin.verticals)}")

    print("\nReady. Replace placeholders in config.json (or AEGIS_* env vars) "
          "and re-run to activate real credentials.")


if __name__ == "__main__":
    main()
