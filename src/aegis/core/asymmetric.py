"""Asymmetric (Ed25519) attestation signing: the verifier cannot forge.

HmacSigner is symmetric: anyone able to verify an attestation holds the key
and can therefore mint one. For regulator-facing proofs use Ed25519: the
`Ed25519Signer` holds the private key (ideally inside KMS/HSM — see
plugins.kms.CloudKmsClient for the managed equivalent), while auditors only
receive the 32-byte public key and verify with `Ed25519Verifier`, which has
no signing capability at all.

Requires the optional `cryptography` package (`pip install cryptography`).
Both classes satisfy the `aegis.core.Signer` protocol (hex-string signatures).
"""
from __future__ import annotations

import secrets
from typing import Protocol

from aegis.core.errors import CryptoBackendUnavailableError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAVE_CRYPTO = True
except ImportError:                       # pragma: no cover - optional dep
    _HAVE_CRYPTO = False


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "Ed25519 signing requires the optional 'cryptography' package: "
            "pip install cryptography")


def default_signer():
    """Preferred attestation signer for new deployments.

    Returns an `Ed25519Signer` (asymmetric: auditors hold only the public
    key and cannot forge) when the optional `cryptography` package is
    installed, otherwise falls back to a random-key `HmacSigner` so the
    system still runs in offline/dev mode. Callers that pass an explicit
    `signer` or `secret` keep their existing behaviour.
    """
    if _HAVE_CRYPTO:
        return Ed25519Signer()
    from aegis.core.attestation import HmacSigner
    return HmacSigner(secrets.token_bytes(32))


class Ed25519Verifier:
    """Verify-only: holds just the public key, cannot sign."""

    def __init__(self, public_key: bytes) -> None:
        _require_crypto()
        if len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self._public_bytes = bytes(public_key)
        self._pk = ed25519.Ed25519PublicKey.from_public_bytes(self._public_bytes)

    @property
    def public_key(self) -> bytes:
        return self._public_bytes

    def sign(self, payload: bytes) -> str:
        raise PermissionError("Ed25519Verifier is verify-only")

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            self._pk.verify(bytes.fromhex(signature), payload)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


class Ed25519Signer:
    """Signs with a private key; `public_key` is safe to publish."""

    def __init__(self, private_key: bytes | None = None) -> None:
        _require_crypto()
        if private_key is None:
            self._sk = ed25519.Ed25519PrivateKey.generate()
        else:
            if len(private_key) != 32:
                raise ValueError("Ed25519 private key must be 32 bytes")
            self._sk = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes(private_key))
        self._verifier = Ed25519Verifier(self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @property
    def public_key(self) -> bytes:
        return self._verifier.public_key

    def verifier(self) -> Ed25519Verifier:
        """A verify-only handle to hand to auditors."""
        return self._verifier

    def sign(self, payload: bytes) -> str:
        return self._sk.sign(payload).hex()

    def verify(self, payload: bytes, signature: str) -> bool:
        return self._verifier.verify(payload, signature)


class PqcKeyExchange(Protocol):
    """Post-quantum key-establishment seam (ML-KEM / Kyber).

    BFSI buyers ask about post-quantum cryptography, not BB84. This protocol
    is the integration point for a PQC KEM (e.g. `liboqs-python` ML-KEM-768):
    `encapsulate` produces a shared secret + ciphertext; `decapsulate`
    recovers the same secret from the ciphertext. The default `PqcKem` is a
    documented placeholder that refuses to run until a real backend is
    injected — it must never silently fall back to classical key exchange.
    """

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (shared_secret, ciphertext)."""
        ...

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret from the ciphertext."""
        ...


class PqcKem:
    """Placeholder PQC KEM. Inject a liboqs-backed implementation before use;
    this class refuses rather than weakening to a classical fallback."""

    def __init__(self, backend: PqcKeyExchange | None = None) -> None:
        self._backend = backend

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        if self._backend is None:
            raise CryptoBackendUnavailableError(
                "PQC KEM requires a liboqs-backed backend; "
                "no classical fallback is provided")
        return self._backend.encapsulate(public_key)

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if self._backend is None:
            raise CryptoBackendUnavailableError(
                "PQC KEM requires a liboqs-backed backend; "
                "no classical fallback is provided")
        return self._backend.decapsulate(private_key, ciphertext)


__all__ = [
    "Ed25519Signer",
    "Ed25519Verifier",
    "PqcKem",
    "PqcKeyExchange",
    "default_signer",
]
