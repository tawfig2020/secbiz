"""Stylometric analyzer (cross-domain: forensic linguistics).

Data payloads (invoices, patient notes, lab results) have a characteristic
register: declarative, third-person, low imperative density. Injected
instructions shift register: imperative mood, second-person address,
agent-targeted vocabulary. Flags sentences that are BOTH imperative AND
agent-directed.

MVP detector #2 of 3 (spec section 5.1).
"""
from __future__ import annotations

from .base import Detection, ScanContext, instruction_density, sentences


class StylometricAnalyzerDetector:
    name = "stylometric_analyzer"

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        canon = ctx.canonical or text
        worst, evidence = 0.0, []
        for sent in sentences(canon):
            d = instruction_density(sent)
            if d >= 0.55:
                if d > worst:
                    worst, evidence = d, [sent[:80]]
        # Multiple moderately-instructive sentences corroborate.
        instructive = sum(1 for s in sentences(canon)
                        if instruction_density(s) >= 0.4)
        if instructive >= 3:
            worst = max(worst, 0.7)
            evidence.append(f"{instructive} instruction-shaped sentences")
        return Detection(self.name, min(worst, 1.0), evidence)
