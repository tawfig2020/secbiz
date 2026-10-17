"""Executor Agent: trusted zone (Pillar 3 / spec 6.1).

Executes only CapabilityTokens minted by the Reference Monitor. It has no
natural-language input path at all -- execute() refuses anything that is not
a verifiable, unexpired, single-use token.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from aegis.capability_bounded.reference_monitor import (
    CapabilityToken,
    ReferenceMonitor,
)
from aegis.core.audit import AuditLog
from aegis.core.observability import metrics


@dataclass(frozen=True)
class ExecResult:
    executed: bool
    action: str
    reason: str
    output: Any = None


class ExecutorAgent:
    name = "executor_agent"

    def __init__(self, monitor: ReferenceMonitor, audit: AuditLog) -> None:
        self._monitor = monitor
        self._audit = audit
        self._tools: dict[str, Callable[..., Any]] = {}

    def register_tool(self, action: str, fn: Callable[..., Any]) -> None:
        self._tools[action] = fn

    def execute(self, token) -> ExecResult:
        if not isinstance(token, CapabilityToken):
            self._audit.record(self.name, "refuse",
                               {"reason": "input is not a capability token"})
            metrics.counter("aegis_execution_total",
                            {"action": "<none>", "outcome": "refused"}).inc()
            return ExecResult(False, "<none>",
                              "refused: natural language / unstructured input "
                              "has no execution path")
        if not self._monitor.verify(token):
            self._audit.record(self.name, "refuse",
                               {"action": token.action,
                                "reason": "bad/expired/replayed token"})
            metrics.counter("aegis_execution_total",
                            {"action": token.action, "outcome": "refused"}).inc()
            return ExecResult(False, token.action,
                              "refused: token failed verification")

        tool = self._tools.get(token.action)
        if tool is None:
            return ExecResult(False, token.action, "no tool bound to action")

        # Atomic verify+burn BEFORE side effects: concurrent executions of
        # one token (double wire transfer) are impossible; at-most-once.
        if not self._monitor.redeem(token):
            self._audit.record(self.name, "refuse",
                               {"action": token.action,
                                "reason": "replayed/concurrent token"})
            metrics.counter("aegis_execution_total",
                            {"action": token.action, "outcome": "refused"}).inc()
            return ExecResult(False, token.action,
                              "refused: token already redeemed")

        params = token.params()          # trust ONLY the signed params
        try:
            output = tool(**params)
        except Exception as exc:
            self._audit.record(self.name, "execute_failed",
                               {"action": token.action,
                                "error": type(exc).__name__})
            metrics.counter("aegis_execution_total",
                            {"action": token.action, "outcome": "failed"}).inc()
            return ExecResult(False, token.action,
                              f"tool failed: {type(exc).__name__}")
        self._audit.record(self.name, "execute",
                           {"action": token.action, "params": params})
        metrics.counter("aegis_execution_total",
                        {"action": token.action, "outcome": "executed"}).inc()
        return ExecResult(True, token.action,
                          "executed under capability token", output)
