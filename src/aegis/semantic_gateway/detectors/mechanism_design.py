"""Mechanism-design detector (cross-domain: game theory / economics).

Treats the agent's permission system as a mechanism and detects payloads
that try to game it: claimed authority ("I am the administrator"),
pre-authorization claims ("this transfer is already approved"), and
incentive/urgency coercion ("emergency override", "you will be rewarded",
"required for compliance"). A well-designed mechanism ignores claimed
authority arriving over the untrusted channel -- this detector makes the
attempt visible.
"""
from __future__ import annotations

import re

from .base import Detection, ScanContext

_AUTHORITY = re.compile(
    r"\b(i\s+am|this\s+is)\s+(the\s+|your\s+)?(system\s+)?"
    r"(administrator|admin|security\s+team|it\s+department|compliance\s+"
    r"officer|developer|operator|root|superuser)\b",
    re.IGNORECASE)

_PREAUTH = re.compile(
    r"\b(this|the|transaction|transfer|request|action|operation)\s+"
    r"(is|has\s+been|was)\s+(already\s+)?(approved|authorized|pre-?approved|"
    r"pre-?authorized|cleared|verified|signed)\b",
    re.IGNORECASE)

_URGENCY = re.compile(
    r"\b(emergency\s+override|urgent|immediately|do\s+not\s+(delay|verify|"
    r"question)|skip\s+(verification|approval|checks?)|time-?sensitive|"
    r"you\s+will\s+be\s+(rewarded|compensated)|required\s+(for|by)\s+"
    r"(compliance|audit|regulation))\b",
    re.IGNORECASE)


class MechanismDesignDetector:
    name = "mechanism_design"

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        surfaces = [s for s in (ctx.canonical or text, ctx.leet)
                    if s is not None]
        signals, evidence = 0.0, []
        m = next((m for s in surfaces for m in [_AUTHORITY.search(s)] if m),
                 None)
        if m:
            signals += 0.6
            evidence.append(f"authority claim: '{m.group(0)}'")
        m = next((m for s in surfaces for m in [_PREAUTH.search(s)] if m),
                 None)
        if m:
            signals += 0.5
            evidence.append(f"pre-authorization claim: '{m.group(0)}'")
        if any(_URGENCY.search(s) for s in surfaces):
            signals += 0.35
            evidence.append("urgency/coercion framing")
        return Detection(self.name, min(signals, 1.0), evidence)
