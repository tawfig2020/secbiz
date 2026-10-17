"""Baseline comparison agent (spec 7.2 demo / 8.3 benchmark row).

Models the industry status quo: an LLM agent fronted by "standard
guardrails" -- a keyword denylist plus a stern system prompt -- but with
NO capability contract and NO out-of-model reference monitor. Model output
is invoked as a tool call directly, so any injection that evades the
keyword filter executes with full tool privileges.

Exists to prove the thesis: in-model defenses are bypassable; only
enforcement outside the model (Pillar 3) provides provable containment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from aegis.capability_bounded.reference_monitor import Action


class KeywordGuardrail:
    """'Standard' prompt guardrail: a denylist regex over the raw prompt.

    Deliberately shallow -- this is what shipped guardrails look like.
    "Ignore previous instructions" does not match `ignore all`; indirect
    phrasing, unicode tricks and buried payloads all sail through.
    """

    _BLOCK = re.compile(
        r"ignore\s+all|jailbreak|\bDAN\b|bypass\s+safety|system\s+prompt\s+hack",
        re.IGNORECASE)

    def allows(self, text: str) -> bool:
        return self._BLOCK.search(text) is None


@dataclass(frozen=True)
class BaselineResult:
    executed: bool
    action: str
    reason: str
    output: Any = None


class BaselineGuardedAgent:
    """LangChain-style agent: guardrail screen -> model -> direct tool call.

    There is no trusted boundary: whatever action name/params the model
    emits is dispatched to a registered tool with ambient authority.
    """

    name = "baseline_agent"

    def __init__(self, model_fn: Callable[[str], Action],
                 guardrail: KeywordGuardrail | None = None) -> None:
        self.model_fn = model_fn
        self.guardrail = guardrail or KeywordGuardrail()
        self._tools: dict[str, Callable[..., Any]] = {}

    def register_tool(self, action: str, fn: Callable[..., Any]) -> None:
        self._tools[action] = fn

    def process(self, text: str) -> BaselineResult:
        if not self.guardrail.allows(text):
            return BaselineResult(False, "<blocked>",
                                  "guardrail keyword match")
        # Trust the model's structured output implicitly -- the exploit path.
        action = self.model_fn(text)
        name = action.name if isinstance(action, Action) else str(action)
        params = dict(action.params) if isinstance(action, Action) else {}
        tool = self._tools.get(name)
        if tool is None:
            return BaselineResult(False, name, "no tool bound")
        try:
            output = tool(**params)
        except Exception as exc:                       # tool errors aren't a defense
            return BaselineResult(False, name, f"tool error: {exc}")
        return BaselineResult(True, name, "executed with ambient authority",
                              output)
