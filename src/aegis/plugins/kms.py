"""KMS-backed signer for the Enterprise/Regulated tier.

The signing key never leaves hardware: a KmsSigner delegates sign/verify to
a Cloud KMS client and refuses to operate without one (no silent fallback to
HMAC). FakeKmsClient simulates the hardware boundary in-memory for tests and
local demos — it holds the key internally and exposes only sign/verify.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Protocol


class KmsClient(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class FakeKmsClient:
    """In-memory KMS: key stays private; only sign/verify are exposed."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._key, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


class KmsSigner:
    """Signer adapter over a KMS client (matches aegis.core.Signer).

    sign() returns a hex string; verify() accepts a hex string. Without a
    client both raise RuntimeError — the key must never silently downgrade
    to a local HMAC secret in a regulated deployment.
    """

    def __init__(self, client: KmsClient | None = None,
                 key_id: str = "aegis-attestation") -> None:
        self.client = client
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        if self.client is None:
            raise RuntimeError("KmsSigner requires a KMS client")
        return self.client.sign(payload).hex()

    def verify(self, payload: bytes, signature: str) -> bool:
        if self.client is None:
            raise RuntimeError("KmsSigner requires a KMS client")
        return self.client.verify(payload, bytes.fromhex(signature))


class CloudKmsClient:
    """Adapter for a real Cloud KMS / HSM client.

    The SDK client is injected as sign/verify callables so this module stays
    dependency-free. Example (Google Cloud KMS asymmetric sign):

        from google.cloud import kms
        client = kms.KeyManagementServiceClient()
        def sign(payload):
            resp = client.asymmetric_sign(request={
                "name": key_version,
                "digest": {"sha256": hashlib.sha256(payload).digest()}})
            return resp.signature
        def verify(payload, signature):
            resp = client.asymmetric_verify(request={
                "name": key_version,
                "digest": {"sha256": hashlib.sha256(payload).digest()},
                "signature": signature})
            return resp.verified
        signer = KmsSigner(CloudKmsClient(sign, verify), key_id=key_version)
    """

    def __init__(self, sign_fn, verify_fn) -> None:
        self._sign = sign_fn
        self._verify = verify_fn

    def sign(self, payload: bytes) -> bytes:
        return self._sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return self._verify(payload, signature)


__all__ = ["CloudKmsClient", "FakeKmsClient", "KmsClient", "KmsSigner"]
