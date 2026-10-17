"""Key management for MTAC (spec 6.1: Cloud KMS integration point).

KeyManager produces per-epoch keys. LocalKeyManager derives them from a
master secret via HMAC (fully offline). KMSKeyManager is the Cloud KMS
adapter point: it delegates to a client exposing
`derive_epoch_key(key_name, epoch) -> bytes`; without a client it refuses
rather than silently weakening to local keys.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Protocol


class KeyManager(Protocol):
    def epoch_key(self, epoch: int) -> bytes:
        ...


class LocalKeyManager:
    """Offline key hierarchy: epoch_key = HMAC(master, epoch)."""

    def __init__(self, master: bytes | None = None) -> None:
        self._master = master or secrets.token_bytes(32)

    def epoch_key(self, epoch: int) -> bytes:
        return hmac.new(self._master, f"epoch:{epoch}".encode(),
                        hashlib.sha256).digest()


class KMSKeyManager:
    """Cloud KMS adapter. The client must expose
    derive_epoch_key(key_name: str, epoch: int) -> bytes
    (e.g. a wrapper over google.cloud.kms macVerify/derive). Refuses to
    operate without a client -- no silent fallback to weaker keys."""

    def __init__(self, client=None, key_name: str = "aegis-mtac-epoch") -> None:
        self.client = client
        self.key_name = key_name

    def epoch_key(self, epoch: int) -> bytes:
        if self.client is None:
            raise RuntimeError(
                "KMSKeyManager requires a Cloud KMS client; "
                "use LocalKeyManager for offline/demo operation")
        return self.client.derive_epoch_key(self.key_name, epoch)
