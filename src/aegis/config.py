"""Runtime configuration with placeholder defaults.

All secrets and GCP resources are placeholders for now. Replace them with
real values (via environment variables or a JSON config file) once
credentials are provisioned. The loader never contacts the network or a
secret store — it only reads local config.

Loading precedence (highest wins):
  1. AEGIS_* environment variables
  2. JSON config file (e.g. config.json)
  3. Placeholder defaults on `Settings`
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Mapping

ENV_PREFIX = "AEGIS_"


@dataclass
class Settings:
    environment: str = "local"              # local | staging | production

    # GCP / Cloud Run
    gcp_project_id: str = "REPLACE_ME_PROJECT_ID"
    gcp_region: str = "us-central1"
    cloud_run_service: str = "aegis"

    # Cloud KMS (attestation signing key)
    kms_provider: str = "fake"              # fake | gcp
    kms_key_ring: str = "aegis-keyring"
    kms_key: str = "aegis-attestation-key"
    kms_key_version: str = "1"

    # Semantic judge (Vertex AI Gemini)
    gemini_model: str = "gemini-2.5-flash"
    gemini_project: str = "REPLACE_ME_PROJECT_ID"
    gemini_location: str = "us-central1"

    # Threat-intel feeds
    feed_fsisac_url: str = "https://feeds.fsisac.com/aegis/signatures.json"
    feed_hisac_url: str = "https://feeds.h-isac.org/aegis/signatures.json"
    feed_cisa_url: str = "https://feeds.cisa.gov/aegis/signatures.json"
    # Secrets: repr=False keeps them out of logs / tracebacks.
    feed_fsisac_api_key: str = field(
        default="REPLACE_ME_FSISAC_API_KEY", repr=False)
    feed_hisac_api_key: str = field(
        default="REPLACE_ME_HISAC_API_KEY", repr=False)
    feed_cisa_api_key: str = field(
        default="REPLACE_ME_CISA_API_KEY", repr=False)

    # Billing
    stripe_api_key: str = field(
        default="REPLACE_ME_STRIPE_API_KEY", repr=False)

    # Persistence
    database_url: str = field(default="REPLACE_ME_DATABASE_URL", repr=False)

    @property
    def kms_key_version_resource(self) -> str:
        """Full Cloud KMS CryptoKeyVersion resource name."""
        return (f"projects/{self.gcp_project_id}/locations/{self.gcp_region}"
                f"/keyRings/{self.kms_key_ring}/cryptoKeys/{self.kms_key}"
                f"/cryptoKeyVersions/{self.kms_key_version}")

    def placeholders(self) -> dict[str, str]:
        """Fields still carrying a REPLACE_ME placeholder."""
        return {k: v for k, v in asdict(self).items()
                if isinstance(v, str) and v.startswith("REPLACE_ME")}

    def is_ready(self) -> bool:
        return not self.placeholders()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_settings(path: str | None = None,
                  env: Mapping[str, str] | None = None) -> Settings:
    """Load from a JSON file, then override with AEGIS_* env vars."""
    data: dict[str, Any] = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data.update(json.load(f))

    env = env if env is not None else os.environ
    field_names = {f.name for f in fields(Settings)}
    for name in field_names:
        key = ENV_PREFIX + name.upper()
        if key in env:
            data[name] = env[key]

    return Settings(**{k: v for k, v in data.items() if k in field_names})


__all__ = ["ENV_PREFIX", "Settings", "load_settings"]
