"""Spectral signal detector (cross-domain: signal processing).

Analyzes the payload's statistical spectrum: character entropy, special-char
density, and long base64-like blobs. Encoded exfil channels and encrypted
payloads produce signatures natural language never does.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .base import Detection, ScanContext

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{120,}\b")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


class SpectralSignalDetector:
    name = "spectral_signal"

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        canon = ctx.canonical or text
        score, evidence = 0.0, []

        if _B64_BLOB.search(canon):
            score = max(score, 0.6)
            evidence.append("base64-like blob")
        if _HEX_BLOB.search(canon):
            score = max(score, 0.55)
            evidence.append("long hex blob")
        if len(canon) > 60:
            specials = sum(1 for c in canon
                           if not c.isalnum() and not c.isspace())
            if specials / len(canon) > 0.35:
                score = max(score, 0.55)
                evidence.append(f"special-char density "
                                f"{specials / len(canon):.2f}")
        if len(canon) > 40 and _entropy(canon) > 5.0 and _B64_BLOB.search(canon):
            score = max(score, 0.8)
            evidence.append("high-entropy encoded payload")
        return Detection(self.name, score, evidence)
