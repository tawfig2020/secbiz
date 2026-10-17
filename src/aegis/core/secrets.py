"""Secrets abstraction: one interface, swappable backends.

`config.py` reads env/JSON; this module is the *runtime* secret source.
Production swaps the backend (KMS/HSM/Vault) without touching callers —
the same `get_secret("aegis.signing.key")` call works everywhere.

Backends:
    EnvSecretsProvider     — os.environ (dev / local)
    KmsSecretsProvider     — Cloud KMS/HSM (key never leaves hardware)
    VaultSecretsProvider   — HashiCorp Vault KV v2 (via injected client)
    ChainedSecretsProvider — try providers in order, first hit wins

All providers raise `SecretUnavailableError` (never return None) so a
missing secret is a loud, fail-closed event rather than a silent `None`.
"""
from __future__ import annotations

import os
from typing import Mapping, Protocol

from aegis.core.errors import SecretUnavailableError


class SecretsProvider(Protocol):
    def get_secret(self, name: str) -> str: ...

    def has_secret(self, name: str) -> bool: ...


class EnvSecretsProvider:
    """Reads secrets from environment variables (AEGIS_* by convention)."""

    def __init__(self, env: Mapping[str, str] | None = None,
                 prefix: str = "AEGIS_") -> None:
        self._env = env if env is not None else os.environ
        self._prefix = prefix

    def _key(self, name: str) -> str:
        return self._prefix + name.upper().replace(".", "_").replace("-", "_")

    def get_secret(self, name: str) -> str:
        key = self._key(name)
        value = self._env.get(key)
        if value is None or value == "":
            raise SecretUnavailableError(
                f"secret {name!r} not found in environment ({key})",
                code="INFRA_SECRET_UNAVAILABLE")
        return value

    def has_secret(self, name: str) -> bool:
        return bool(self._env.get(self._key(name)))


class KmsSecretsProvider:
    """Cloud KMS/HSM-backed secret access. The client must expose
    `access_secret_version(resource_name) -> str`. Refuses to operate
    without a client — no silent fallback to weaker storage."""

    def __init__(self, client, project: str, region: str,
                 keyring: str, key: str) -> None:
        self._client = client
        self._project = project
        self._region = region
        self._keyring = keyring
        self._key = key

    def _resource(self, name: str) -> str:
        version = name.replace(".", "-")
        return (f"projects/{self._project}/locations/{self._region}"
                f"/keyRings/{self._keyring}/cryptoKeys/{self._key}"
                f"/cryptoKeyVersions/{version}")

    def get_secret(self, name: str) -> str:
        if self._client is None:
            raise SecretUnavailableError(
                f"KmsSecretsProvider requires a client to read {name!r}",
                code="INFRA_SECRET_UNAVAILABLE")
        return self._client.access_secret_version(self._resource(name))

    def has_secret(self, name: str) -> bool:
        return self._client is not None


class VaultSecretsProvider:
    """HashiCorp Vault KV v2. The client must expose
    `read(path) -> {"data": {"data": {key: value}}}`."""

    def __init__(self, client, mount: str = "secret",
                 base_path: str = "aegis") -> None:
        self._client = client
        self._mount = mount
        self._base_path = base_path

    def get_secret(self, name: str) -> str:
        if self._client is None:
            raise SecretUnavailableError(
                f"VaultSecretsProvider requires a client to read {name!r}",
                code="INFRA_SECRET_UNAVAILABLE")
        path = f"{self._mount}/data/{self._base_path}/{name}"
        resp = self._client.read(path)
        try:
            return resp["data"]["data"]["value"]
        except (KeyError, TypeError) as exc:
            raise SecretUnavailableError(
                f"secret {name!r} missing at {path}",
                code="INFRA_SECRET_UNAVAILABLE") from exc

    def has_secret(self, name: str) -> bool:
        return self._client is not None


class ChainedSecretsProvider:
    """Try providers in order; the first that has the secret wins."""

    def __init__(self, *providers: SecretsProvider) -> None:
        self._providers = providers

    def get_secret(self, name: str) -> str:
        for provider in self._providers:
            if provider.has_secret(name):
                return provider.get_secret(name)
        raise SecretUnavailableError(
            f"secret {name!r} not found in any provider",
            code="INFRA_SECRET_UNAVAILABLE")

    def has_secret(self, name: str) -> bool:
        return any(p.has_secret(name) for p in self._providers)


__all__ = [
    "ChainedSecretsProvider",
    "EnvSecretsProvider",
    "KmsSecretsProvider",
    "SecretsProvider",
    "VaultSecretsProvider",
]
