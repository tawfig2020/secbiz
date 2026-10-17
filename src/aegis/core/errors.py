"""Unified error taxonomy for Aegis.

Fail-closed logic, attestations, and audit logs all need to distinguish
*why* something failed. A single hierarchy gives every layer a stable,
compliance-friendly vocabulary:

    AegisError
    ├── DomainError      — the request itself is invalid (bad action/params)
    │     └── PolicyError — valid request, but the contract forbids it
    ├── ProtocolError    — malformed wire input / token / attestation
    └── InfraError       — storage, KMS, network, or other dependency failure

Every error carries a stable `code` (for audit/compliance queries) and an
optional `correlation_id` (for tracing). Fail-closed callers can branch on
`is_safe_to_deny` / `is_safe_to_abort` without string-matching messages.
"""
from __future__ import annotations

from typing import Any


class AegisError(Exception):
    """Base class for every Aegis-raised error."""

    code = "AEGIS_ERROR"
    category = "unknown"

    def __init__(self, message: str, *, code: str | None = None,
                 correlation_id: str | None = None,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.code
        self.correlation_id = correlation_id
        self.details = details or {}

    # -- fail-closed guidance -------------------------------------------
    @property
    def is_safe_to_deny(self) -> bool:
        """True when the error is attributable to the request (deny it),
        not to our own infrastructure (which may need an abort/retry)."""
        return self.category in ("domain", "policy", "protocol")

    @property
    def is_safe_to_abort(self) -> bool:
        """True when the error is our own fault: abort, don't fabricate a
        verdict against an innocent request."""
        return self.category == "infra"

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "details": self.details,
        }


class DomainError(AegisError):
    """The request is well-formed but semantically invalid (unknown action,
    missing evidence, out-of-range parameter)."""

    category = "domain"


class PolicyError(DomainError):
    """The request is valid but the capability contract denies it.
    Distinct from DomainError so audit can separate 'bad input' from
    'correctly refused by policy'."""

    category = "policy"


class ProtocolError(AegisError):
    """Malformed wire input: bad token, bad signature, bad attestation,
    non-JSON body, oversized payload."""

    category = "protocol"


class InfraError(AegisError):
    """Dependency failure: storage, KMS/HSM, network, or a missing optional
    backend (e.g. `cryptography` not installed)."""

    category = "infra"


# -- concrete, stable-coded errors --------------------------------------
class UnknownContractError(PolicyError):
    code = "POLICY_UNKNOWN_CONTRACT"


class ProhibitedActionError(PolicyError):
    code = "POLICY_PROHIBITED_ACTION"


class ConstraintViolationError(PolicyError):
    code = "POLICY_CONSTRAINT_VIOLATION"


class HumanApprovalRequiredError(PolicyError):
    code = "POLICY_HUMAN_APPROVAL_REQUIRED"


class DelegationError(PolicyError):
    code = "POLICY_DELEGATION_VIOLATION"


class InvalidTokenError(ProtocolError):
    code = "PROTOCOL_INVALID_TOKEN"


class InvalidAttestationError(ProtocolError):
    code = "PROTOCOL_INVALID_ATTESTATION"


class InvalidSignatureError(ProtocolError):
    code = "PROTOCOL_INVALID_SIGNATURE"


class SecretUnavailableError(InfraError):
    code = "INFRA_SECRET_UNAVAILABLE"


class StorageError(InfraError):
    code = "INFRA_STORAGE"


class CryptoBackendUnavailableError(InfraError):
    code = "INFRA_CRYPTO_BACKEND_UNAVAILABLE"


__all__ = [
    "AegisError",
    "ConstraintViolationError",
    "CryptoBackendUnavailableError",
    "DelegationError",
    "DomainError",
    "HumanApprovalRequiredError",
    "InfraError",
    "InvalidAttestationError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "PolicyError",
    "ProhibitedActionError",
    "ProtocolError",
    "SecretUnavailableError",
    "StorageError",
    "UnknownContractError",
]
