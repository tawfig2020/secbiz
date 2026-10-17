"""Reference Monitor: out-of-model enforcement (spec section 6.2).

evaluate(action, context) -> MonitorResult runs OUTSIDE the model. Order of
checks mirrors the spec pseudocode:
    prohibited  -> DENY
    constraints -> DENY on violation
    human-gated -> DEFER_HUMAN (never auto-executes)
    permitted   -> ALLOW + mint single-use HMAC capability token

The model never sees the signing key; a hijacked Reader cannot mint authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping

from aegis.capability_bounded.capability_contract import (
    CapabilityContract,
    validate,
)
from aegis.capability_bounded.delegation import (
    DelegationError,
    delegate_contract,
)
from aegis.core.asymmetric import default_signer
from aegis.core.audit import AuditLog
from aegis.core.attestation import (
    Attestation,
    HmacSigner,
    Signer,
    sign_attestation,
)
from aegis.core.observability import Correlation, DECISION_COUNTER, metrics


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER_HUMAN = "DEFER_HUMAN"


@dataclass(frozen=True)
class Action:
    name: str
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Context:
    contract_id: str
    source_id: str = "default"
    subject: str = "reader_agent"


@dataclass(frozen=True)
class CapabilityToken:
    contract_id: str
    action: str
    params_json: str
    nonce: str
    expires_at: float
    signature: str

    def params(self) -> dict:
        return json.loads(self.params_json)


@dataclass(frozen=True)
class MonitorResult:
    decision: Decision
    reason: str
    token: CapabilityToken | None = None
    attestation: Attestation | None = None   # this decision's own proof

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


class ReferenceMonitor:
    def __init__(self, contracts: Mapping[str, CapabilityContract],
                 audit: AuditLog, secret: bytes | None = None,
                 token_ttl: float = 30.0, event_bus=None,
                 signer: Signer | None = None,
                 approval_queue=None, attestation_store=None) -> None:
        if isinstance(contracts, CapabilityContract):      # convenience
            contracts = {contracts.contract_id: contracts}
        self._contracts = dict(contracts)
        self.audit = audit
        self._key = secret or secrets.token_bytes(32)
        self._ttl = token_ttl
        self._issued_nonce: dict[str, float] = {}   # nonce -> expires_at
        self._bus = event_bus
        # Attestation signer: explicit signer wins; an explicit secret keeps
        # symmetric HMAC; otherwise default to Ed25519 (asymmetric) so the
        # verifier cannot forge regulator-facing proofs.
        if signer is not None:
            self._signer = signer
        elif secret is not None:
            self._signer = HmacSigner(secret)
        else:
            self._signer = default_signer()
        self._approvals = approval_queue
        self._store = attestation_store
        self._attestations: list[Attestation] = (
            attestation_store.load() if attestation_store else [])
        # Guards attestations, nonce store and contract registry so the
        # monitor is safe under threaded servers.
        self._lock = threading.RLock()

    @property
    def attestation_log(self) -> tuple[Attestation, ...]:
        """Append-only, independently verifiable proof of every decision."""
        with self._lock:
            return tuple(self._attestations)

    def _keep(self, att: Attestation) -> None:
        """Persist (if configured) then expose; durable-first so a crash
        can never leave a visible-but-unstored proof."""
        with self._lock:
            if self._store is not None:
                self._store.append(att)
            self._attestations.append(att)

    def _attest(self, result: MonitorResult, action: Action,
                context: Context) -> Attestation:
        att = sign_attestation(signer=self._signer,
                               contract_id=context.contract_id,
                               action=action.name,
                               decision=result.decision.value,
                               reason=result.reason,
                               subject=context.subject,
                               params=action.params)
        self._keep(att)
        self.audit.record("attestation", "signed",
                          {"action": action.name,
                           "decision": result.decision.value,
                           "signature": att.signature[:16]})
        return att

    def _emit(self, result: MonitorResult, action: Action,
              context: Context, latency_ms: float,
              attestation_sig: str = "") -> None:
        if self._bus is not None:
            try:
                self._bus.emit("contract_decision", "reference_monitor",
                               f"{result.decision.value} {action.name}",
                               decision=result.decision.value,
                               action=action.name,
                               contract_id=context.contract_id,
                               subject=context.subject,
                               reason=result.reason,
                               latency_ms=round(latency_ms, 2),
                               attestation=attestation_sig,
                               correlation_id=Correlation.get())
            except Exception:  # telemetry must never break enforcement
                pass

    # -- spec interface --------------------------------------------------
    def contract(self, contract_id: str) -> CapabilityContract:
        return self._contracts[contract_id]

    def evaluate(self, action: Action, context: Context) -> MonitorResult:
        """Mediate one action request. Runs outside the model."""
        t0 = time.perf_counter()
        result = self._decide(action, context)
        metrics.counter(DECISION_COUNTER, {
            "decision": result.decision.value,
            "contract": context.contract_id,
        }).inc()
        att = self._attest(result, action, context)
        result = replace(result, attestation=att)
        if (result.decision is Decision.DEFER_HUMAN
                and self._approvals is not None):
            try:
                self._approvals.enqueue(action, context, result.reason)
            except Exception:  # queue failure must not break mediation
                pass
        self._emit(result, action, context,
                   (time.perf_counter() - t0) * 1000,
                   attestation_sig=att.signature[:16])
        return result

    # -- delegation (strict attenuation) ----------------------------------
    def delegate(self, parent_id: str, requested: CapabilityContract,
                 subject: str = "") -> CapabilityContract:
        """Register a child contract under strict attenuation and mint a
        parent->child attestation preserving the provenance chain.
        Raises DelegationError on scope/drift/depth violations."""
        parent = self._contracts.get(parent_id)
        if parent is None:
            raise DelegationError(
                f"unknown parent contract {parent_id!r}")
        child = delegate_contract(parent, requested)
        att = sign_attestation(
            signer=self._signer, contract_id=child.contract_id,
            action="delegate", decision="REGISTERED",
            reason=f"attenuated from {parent.contract_id}",
            subject=subject or parent_id,
            params={"parent": parent.contract_id,
                    "depth": child.delegation_depth})
        with self._lock:
            self._keep(att)
            self._contracts[child.contract_id] = child
        self.audit.record("delegation", "registered",
                          {"parent": parent.contract_id,
                           "child": child.contract_id,
                           "depth": child.delegation_depth,
                           "signature": att.signature[:16]})
        if self._bus is not None:
            try:
                self._bus.emit("delegation", "reference_monitor",
                               f"delegated {parent.contract_id} -> "
                               f"{child.contract_id} "
                               f"(depth {child.delegation_depth})",
                               parent=parent.contract_id,
                               child=child.contract_id,
                               depth=child.delegation_depth,
                               attestation=att.signature[:16])
            except Exception:
                pass
        return child

    def _decide(self, action: Action, context: Context) -> MonitorResult:
        contract = self._contracts.get(context.contract_id)
        if contract is None:
            self.audit.record("reference_monitor", "deny",
                              {"reason": "unknown contract",
                               "contract_id": context.contract_id})
            return MonitorResult(Decision.DENY,
                                 f"unknown contract {context.contract_id!r}")

        errors = validate(contract, action.name, action.params)
        if errors:
            reason = "; ".join(errors)
            prohibited = action.name in contract.prohibited_actions
            self.audit.record("reference_monitor",
                              "deny_prohibited" if prohibited else "deny",
                              {"action": action.name, "errors": errors})
            return MonitorResult(Decision.DENY, reason)

        spec = contract.permitted_actions.get(action.name)
        if spec is not None and spec.requires_human_approval:
            self.audit.record("reference_monitor", "defer_human",
                              {"action": action.name})
            return MonitorResult(Decision.DEFER_HUMAN,
                                 f"action {action.name!r} requires human "
                                 f"approval under {contract.contract_id}")

        token = self._mint(contract, action)
        self.audit.record("reference_monitor", "allow",
                          {"action": action.name,
                           "contract_id": contract.contract_id})
        return MonitorResult(Decision.ALLOW,
                             "permitted by capability contract", token)

    # -- token machinery ---------------------------------------------------
    def _mint(self, contract: CapabilityContract, action: Action) -> CapabilityToken:
        params_json = json.dumps(action.params, sort_keys=True,
                                 separators=(",", ":"), default=str)
        now = time.time()
        nonce, exp = secrets.token_hex(8), now + self._ttl
        sig = self._token_sig(contract.contract_id, action.name,
                              params_json, nonce, exp)
        with self._lock:
            self._prune_nonces(now)
            self._issued_nonce[nonce] = exp
        return CapabilityToken(contract.contract_id, action.name,
                               params_json, nonce, exp, sig)

    def _prune_nonces(self, now: float) -> None:
        """Drop expired nonces so the store cannot grow without bound."""
        expired = [n for n, exp in self._issued_nonce.items() if exp < now]
        for n in expired:
            del self._issued_nonce[n]

    def _token_sig(self, contract_id: str, action: str, params_json: str,
                   nonce: str, exp: float) -> str:
        payload = json.dumps(["aegis.token.v1", contract_id, action,
                              params_json, nonce, f"{exp:.6f}"],
                             separators=(",", ":"))
        return hmac.new(self._key, payload.encode(),
                        hashlib.sha256).hexdigest()

    def verify(self, token: CapabilityToken,
               *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            known = token.nonce in self._issued_nonce
        if now > token.expires_at or not known:
            return False
        expected = self._token_sig(token.contract_id, token.action,
                                   token.params_json, token.nonce,
                                   token.expires_at)
        return hmac.compare_digest(expected, token.signature)

    def consume(self, token: CapabilityToken) -> None:
        with self._lock:
            self._issued_nonce.pop(token.nonce, None)

    def redeem(self, token: CapabilityToken) -> bool:
        """Atomically verify AND burn a token (at-most-once execution).
        Two racing executors can never both succeed."""
        with self._lock:
            if not self.verify(token):
                return False
            self._issued_nonce.pop(token.nonce, None)
            return True
