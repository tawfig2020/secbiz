"""Taint tracker (cross-domain: program analysis).

Taint analysis for natural language: text arriving inside a *data carrier*
(labeled fields, quoted blocks, embedded document sections) is tainted as
content, not commands. If instruction-shaped sentences appear inside such
spans -- a 'patient note' giving orders, an 'invoice line' invoking tools --
the data->instruction boundary has been violated.
"""
from __future__ import annotations

import re
from itertools import islice

from .base import Detection, ScanContext, instruction_density, sentences

_MAX_MARKERS = 64

# Markers that declare what follows is *data*, not instructions.
_DATA_MARKER = re.compile(
    r"(patient\s+(note|record|history)|lab\s+results?|clinical\s+note|"
    r"invoice|receipt|kyc\s+(document|upload|form)|attached\s+(file|document)|"
    r"email\s+body|message\s+content|comment|review|description|"
    r"<(doc|document|data|content|record)>)",
    re.IGNORECASE)


class TaintTrackerDetector:
    name = "taint_tracker"

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        worst, evidence = 0.0, []
        for canon in dict.fromkeys((ctx.canonical or text, ctx.leet)):
            # Bounded work: attacker-controlled marker floods must not
            # multiply the 600-char region scan.
            markers = list(islice(_DATA_MARKER.finditer(canon),
                                  _MAX_MARKERS))
            for m in markers:
                # Tainted region: 600 chars following the data marker.
                region = canon[m.end():m.end() + 600]
                for sent in sentences(region):
                    d = instruction_density(sent)
                    if d >= 0.5 and d > worst:
                        worst, evidence = d, [
                            f"instruction inside '{m.group(0)}' field: "
                            f"{sent[:70]}"]
        # Escalate: explicit data marker + instruction = boundary violation.
        if worst > 0:
            worst = min(1.0, worst + 0.1)
        return Detection(self.name, worst, evidence)
