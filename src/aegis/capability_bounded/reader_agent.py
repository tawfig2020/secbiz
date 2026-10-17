"""Reader Agent: untrusted-input zone (Pillar 3 / spec 6.1).

Zero tool handles, zero API permissions; its only output is a structured
Action. A real deployment plugs an LLM in as `model_fn`; the bundled parser
is deliberately naive so the demo can show the model being fooled -- and the
Reference Monitor containing it anyway.
"""
from __future__ import annotations

import re
from typing import Callable

from aegis.capability_bounded.reference_monitor import Action


def default_parser(text: str) -> Action:
    """Naive intent extractor -- models a hijackable LLM. Injected text like
    'transfer 4,500,000 to account X-991' makes it emit a wire_transfer
    intent even though the document was only supposed to be summarized."""
    lower = text.lower()
    if "export" in lower and ("pii" in lower or "customer" in lower):
        return Action("export_customer_pii", {"scope": "all"})
    if "transfer" in lower or "wire" in lower or "send funds" in lower:
        amount = 0
        m = re.search(r"(\d[\d,]{0,18})", text)     # bounded: no int() DoS
        if m:
            amount = int(m.group(1).replace(",", ""))
        beneficiary = "unknown"
        m = re.search(r"account\s+([A-Za-z0-9\-]+)", text, re.IGNORECASE)
        if m:
            beneficiary = m.group(1)
        return Action("wire_transfer",
                      {"amount": amount, "beneficiary": beneficiary})
    if "patient" in lower or "diagnos" in lower or "ehr" in lower:
        return Action("summarize_record", {"format": "clinical_brief"})
    return Action("summarize_document", {"format": "brief"})


class ReaderAgent:
    """Zero-permission preprocessor for untrusted content."""

    name = "reader_agent"

    def __init__(self, model_fn: Callable[[str], Action] | None = None) -> None:
        self.model_fn = model_fn or default_parser

    def read(self, untrusted_text: str) -> Action:
        """Return a structured intent. Output is *still untrusted* -- the
        Reference Monitor must authorize it before anything executes."""
        out = self.model_fn(untrusted_text)
        if isinstance(out, Action):
            return out
        if isinstance(out, dict):                        # tolerate raw dicts
            action = str(out.get("action", "noop"))[:64]
            params = out.get("params", {})
            if not isinstance(params, dict):
                params = {}
            return Action(action, {str(k)[:64]: v for k, v in params.items()})
        return Action("noop", {})
