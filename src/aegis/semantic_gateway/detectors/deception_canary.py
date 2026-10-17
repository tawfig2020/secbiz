"""Deception canary (cross-domain: honeypots).

The gateway plants canary tokens (fake API keys, phantom records) in tool
outputs and system context. Legitimate content never echoes them; an
injection that coerces the model into dumping context, or an exfil attempt,
surfaces the canary. Two signals:
  * payload literally contains a canary            -> score 1.0 (echo/exfil)
  * payload instructs to reproduce secrets/canary  -> score 0.7
"""
from __future__ import annotations

import re
import secrets as _secrets

from .base import Detection, ScanContext

_COERCE = re.compile(
    r"(repeat|reproduce|echo|include|return|print|output|reveal|disclose)\b"
    r".{0,40}(canary|token|secret|key|verbatim|exact|literal|raw\s+context|"
    r"system\s+prompt|full\s+text)",
    re.IGNORECASE)


def generate_canaries(n: int = 2) -> tuple[str, ...]:
    return tuple(f"AEGIS-CANARY-{_secrets.token_hex(4).upper()}"
                 for _ in range(n))


class DeceptionCanaryDetector:
    name = "deception_canary"

    def __init__(self, canaries: tuple[str, ...] | None = None) -> None:
        self.canaries = canaries or generate_canaries()

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        canon = ctx.canonical or text
        live = set(self.canaries) | set(ctx.canaries)
        echoed = [c for c in live if c and c in canon]
        if echoed:
            return Detection(self.name, 1.0,
                             [f"canary echoed: {e}" for e in echoed])
        if _COERCE.search(canon):
            return Detection(self.name, 0.7,
                             ["payload coerces secret/canary reproduction"])
        return Detection(self.name, 0.0)
