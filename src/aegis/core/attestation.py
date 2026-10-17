"""Signed containment attestations: the 'proves it' half of the thesis.

Every Reference Monitor decision is bound into an Attestation — an
HMAC-signed record of (contract, action, decision, params digest, nonce,
timestamp). A regulator, customer, or auditor can verify an attestation
offline with the key, without trusting the system's own claims. The log
of attestations is append-only evidence that containment *happened*.

Domain separation: attestations sign under the tag "aegis.attest.v1" so a
capability-token signature can never be replayed as an attestation (and
vice versa).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

_DOMAIN = "aegis.attest.v1"


# --------------------------------------------------------------- signers
class Signer(Protocol):
    """Pluggable signing backend. HmacSigner is the offline default;
    wrap a Cloud KMS / HSM call in CallableSigner for production — the
    key then never leaves hardware and an insider cannot mint proofs."""

    def sign(self, payload: bytes) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


class HmacSigner:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload,
                        hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        expected = hmac.new(self._key, payload,
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class CallableSigner:
    """Adapt external sign/verify functions (e.g. KMS asymmetric sign)
    into the Signer protocol. sign_fn returns bytes or hex str."""

    def __init__(self, sign_fn: Callable[[bytes], bytes | str],
                 verify_fn: Callable[[bytes, str], bool] | None = None
                 ) -> None:
        self._sign = sign_fn
        self._verify = verify_fn

    def sign(self, payload: bytes) -> str:
        out = self._sign(payload)
        return out.hex() if isinstance(out, bytes) else out

    def verify(self, payload: bytes, signature: str) -> bool:
        if self._verify is None:
            raise NotImplementedError("no verify_fn supplied")
        return self._verify(payload, signature)


@dataclass(frozen=True)
class Attestation:
    contract_id: str
    action: str
    decision: str                     # ALLOW / DENY / DEFER_HUMAN
    reason: str
    subject: str
    params_digest: str                # sha256 of canonicalized params
    nonce: str
    ts: float
    signature: str


def _payload(att: Attestation) -> str:
    """Canonical, unambiguous signing payload (JSON array, no delimiter
    collisions: a '|' inside `reason`/`subject` cannot shift field bounds)."""
    return json.dumps(
        [_DOMAIN, att.contract_id, att.action, att.decision, att.reason,
         att.subject, att.params_digest, att.nonce, f"{att.ts:.6f}"],
        separators=(",", ":"), ensure_ascii=True)


def sign_attestation(key: bytes | None = None, *, contract_id: str,
                     action: str, decision: str, reason: str, subject: str,
                     params: Mapping[str, Any], now: float | None = None,
                     signer: Signer | None = None) -> Attestation:
    """Mint a signed attestation for a single monitor decision.
    `signer` overrides `key`; exactly one must be supplied."""
    signer = signer or (HmacSigner(key) if key is not None else None)
    if signer is None:
        raise ValueError("sign_attestation requires key or signer")
    digest = hashlib.sha256(
        json.dumps(params, sort_keys=True, default=str).encode()
    ).hexdigest()
    att = Attestation(
        contract_id=contract_id, action=action, decision=decision,
        reason=reason, subject=subject, params_digest=digest,
        nonce=secrets.token_hex(8),
        ts=time.time() if now is None else now,
        signature="")
    sig = signer.sign(_payload(att).encode())
    return Attestation(contract_id=att.contract_id, action=att.action,
                       decision=att.decision, reason=att.reason,
                       subject=att.subject, params_digest=att.params_digest,
                       nonce=att.nonce, ts=att.ts, signature=sig)


def verify_attestation(key: bytes | None, att: Attestation,
                       signer: Signer | None = None) -> bool:
    """Offline verification: recompute/verify the signature over the
    fixed payload. `signer` overrides `key` (e.g. a KMS verify call)."""
    signer = signer or (HmacSigner(key) if key is not None else None)
    if signer is None:
        raise ValueError("verify_attestation requires key or signer")
    try:
        return signer.verify(_payload(att).encode(), att.signature)
    except NotImplementedError:
        raise
    except Exception:
        return False
