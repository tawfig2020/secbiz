"""AgentVault: the single-plugin composition root.

Wires the Aegis containment chain for a banking agent:

    untrusted text -> SemanticGateway -> ReaderAgent -> ReferenceMonitor
                    -> ExecutorAgent -> egress scan

Every monitor decision is minted as a signed attestation a regulator can
verify offline. The model (ReaderAgent) never sees the signing key; the
executor accepts only single-use capability tokens.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from aegis.capability_bounded import (
    Action,
    ApprovalQueue,
    CapabilityContract,
    Context,
    ExecutorAgent,
    ReaderAgent,
    ReferenceMonitor,
)
from aegis.core import (
    Attestation,
    AttestationStore,
    AuditLog,
    default_signer,
    verify_attestation,
)
from aegis.semantic_gateway import GeminiClassifier, SemanticGateway

from .contract import CONTRACT_ID, CONTRACT_JSON
from .gemini_judge import GeminiJudge


@dataclass(frozen=True)
class VaultResult:
    decision: str
    reason: str
    action: str = ""
    executed: bool = False
    output: Any = None
    attestation: dict = field(default_factory=dict)
    inbound: dict = field(default_factory=dict)
    egress: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "action": self.action,
            "executed": self.executed,
            "output": self.output,
            "attestation": self.attestation,
            "inbound": self.inbound,
            "egress": self.egress,
        }


class AgentVault:
    name = "agent_vault"

    def __init__(self, *, data_dir: str | None = None,
                 signing_key: bytes | None = None,
                 gemini_client=None) -> None:
        self.contract = CapabilityContract.from_dict(CONTRACT_JSON)
        self.signer = default_signer()
        self._secret = signing_key or secrets.token_bytes(32)

        if data_dir:
            Path(data_dir).mkdir(parents=True, exist_ok=True)
            self.audit = AuditLog(Path(data_dir) / "audit.db")
            self.store = AttestationStore(Path(data_dir) / "attestations.db")
            self.approvals = ApprovalQueue(
                Path(data_dir) / "approvals.db", signer=self.signer)
        else:
            self.audit = AuditLog()
            self.store = AttestationStore(":memory:")
            self.approvals = ApprovalQueue(":memory:", signer=self.signer)

        # Optional Gemini-on-Vertex-AI judge refines the heuristic fusion
        # head; without it (or on any failure) the gateway stays heuristic.
        client = gemini_client if gemini_client is not None \
            else GeminiJudge.from_env()
        classifier = GeminiClassifier(client) if client is not None else None
        self.gateway = SemanticGateway(classifier=classifier)
        self.classifier_name = classifier.name if classifier is not None \
            else "heuristic"
        self.monitor = ReferenceMonitor(
            {CONTRACT_ID: self.contract}, self.audit,
            secret=self._secret, signer=self.signer,
            approval_queue=self.approvals, attestation_store=self.store)

        self.reader = ReaderAgent()
        self.executor = ExecutorAgent(self.monitor, self.audit)
        self._register_tools()

    def _register_tools(self) -> None:
        self.executor.register_tool(
            "read_transaction",
            lambda **p: {
                "account": "ACC-100",
                "balance": "12,345.67 USD",
                "recent": ["ACC-100 -> ACC-200  $1,200.00"],
            })
        self.executor.register_tool(
            "summarize_document",
            lambda **p: f"[summary: {p.get('format', 'brief')}]")

    # -- full pipeline -----------------------------------------------------
    def process(self, untrusted_text: str,
                source_id: str = "customer") -> VaultResult:
        """Run one untrusted message through the whole containment chain."""
        inbound = self.gateway.scan(untrusted_text, source_id=source_id)
        if inbound.verdict.name == "BLOCK":
            return VaultResult(
                decision="BLOCK",
                reason="inbound semantic gateway blocked the payload",
                inbound={"verdict": inbound.verdict.name,
                         "score": inbound.score,
                         "hits": inbound.detector_hits})

        action = self.reader.read(untrusted_text)
        res = self.monitor.evaluate(
            action, Context(contract_id=CONTRACT_ID, source_id=source_id))
        att = self._attestation_dict(res.attestation)

        if res.decision.value in ("DENY", "DEFER_HUMAN"):
            return VaultResult(decision=res.decision.value, reason=res.reason,
                               action=action.name, attestation=att)

        exec_res = self.executor.execute(res.token)
        egress: dict[str, Any] = {}
        output = exec_res.output
        if exec_res.executed and isinstance(output, str):
            eg = self.gateway.scan_output(output)
            egress = {"verdict": eg.verdict.name, "score": eg.score,
                      "hits": eg.detector_hits, "sanitized": eg.sanitized}
        return VaultResult(decision=res.decision.value, reason=res.reason,
                           action=action.name, executed=exec_res.executed,
                           output=output, attestation=att, egress=egress)

    # -- direct mediation --------------------------------------------------
    def evaluate_action(self, action: str,
                        params: Mapping[str, Any] | None = None,
                        subject: str = "customer",
                        source_id: str = "api") -> dict[str, Any]:
        """Mediate one action; return the decision + signed proof (no exec)."""
        res = self.monitor.evaluate(
            Action(action, params or {}),
            Context(contract_id=CONTRACT_ID, source_id=source_id,
                    subject=subject))
        return {
            "decision": res.decision.value,
            "reason": res.reason,
            "allowed": res.allowed,
            "attestation": self._attestation_dict(res.attestation),
        }

    def mediate(self, action: str, params: Mapping[str, Any] | None = None,
                subject: str = "customer",
                source_id: str = "api") -> dict[str, Any]:
        """Mediate AND execute an allowed action (happy-path demo)."""
        res = self.monitor.evaluate(
            Action(action, params or {}),
            Context(contract_id=CONTRACT_ID, source_id=source_id,
                    subject=subject))
        out: dict[str, Any] = {
            "decision": res.decision.value,
            "reason": res.reason,
            "allowed": res.allowed,
            "attestation": self._attestation_dict(res.attestation),
            "executed": False,
            "output": None,
        }
        if res.allowed and res.token is not None:
            exec_res = self.executor.execute(res.token)
            out["executed"] = exec_res.executed
            out["output"] = exec_res.output
        return out

    def inspect_response(self, output: str) -> dict[str, Any]:
        r = self.gateway.scan_output(output)
        return {"verdict": r.verdict.name, "score": r.score,
                "hits": r.detector_hits, "sanitized": r.sanitized}

    # -- evidence ----------------------------------------------------------
    def attestations(self) -> list[dict[str, Any]]:
        return [self._attestation_dict(a) for a in self.monitor.attestation_log]

    def verify_attestation(self, att: Mapping[str, Any]) -> bool:
        a = Attestation(
            contract_id=att["contract_id"], action=att["action"],
            decision=att["decision"], reason=att["reason"],
            subject=att["subject"], params_digest=att["params_digest"],
            nonce=att["nonce"], ts=att["ts"], signature=att["signature"])
        return verify_attestation(None, a, signer=self.signer)

    @staticmethod
    def _attestation_dict(att) -> dict[str, Any]:
        if att is None:
            return {}
        return {
            "contract_id": att.contract_id,
            "action": att.action,
            "decision": att.decision,
            "reason": att.reason,
            "subject": att.subject,
            "params_digest": att.params_digest,
            "nonce": att.nonce,
            "ts": att.ts,
            "signature": att.signature,
        }
