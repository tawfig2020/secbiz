"""Egress scanner: the outbound half of the Semantic Gateway.

Inbound scanning stops injected *commands*; egress scanning stops a fooled
model from leaking *data*: echoed deception canaries, system-prompt
fragments, PHI/PII, and credential material. Findings at/above block level
deny the response; moderate PII density redacts (sanitize path) instead of
blocking outright.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detectors.base import Detection, canonicalize

# High-severity: credential material that must never leave.
_SECRETS: list[tuple[str, re.Pattern, float]] = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 1.0),
    ("api_token",
     re.compile(r"\b(?:sk-|ghp_|gho_|xox[baprs]-|AIza)[A-Za-z0-9_\-]{10,}\b"),
     1.0),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."
                r"[A-Za-z0-9_\-]{5,}\b"), 1.0),
    ("private_key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY"),
     1.0),
]

# Moderate: regulated PII/PHI. Density redacts; volume escalates to block.
_PII: list[tuple[str, re.Pattern, float]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.8),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\d\b"), 0.8),
    ("mrn", re.compile(r"\bMRN[- ]?\d{4,}\b", re.IGNORECASE), 0.6),
    ("phone",
     re.compile(r"\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"), 0.4),
    # Bounded quantifiers (RFC 5321 limits) keep matching linear-time; the
    # unbounded form was quadratic (~30s on 64KB of 'a.a.a.').
    ("email",
     re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+"), 0.4),
]

# System-prompt leakage markers (plus caller-supplied protected fragments).
_PROMPT_LEAK = re.compile(
    r"(my\s+system\s+prompt|my\s+(full\s+)?instructions\s+(are|say|state)|"
    r"BEGIN\s+SYSTEM\s+PROMPT|you\s+are\s+.{0,40}instructions\s*(?:are|:))",
    re.IGNORECASE)


@dataclass(frozen=True)
class EgressResult:
    score: float                        # 0..1 fused severity
    detections: list[Detection] = field(default_factory=list)
    redacted: str = ""                  # sanitized copy of the output

    @property
    def findings(self) -> dict[str, float]:
        return {d.detector: round(d.score, 3) for d in self.detections
                if d.fired}


class EgressScanner:
    """Scans model/tool outputs before they leave the trust boundary."""

    name = "egress_scanner"

    def __init__(self, canaries: tuple[str, ...] = (),
                 protected_fragments: tuple[str, ...] = (),
                 block_at: float = 0.6,
                 extra_pii=(), extra_secrets=()) -> None:
        self.canaries = canaries
        self.protected_fragments = protected_fragments
        self.block_at = block_at
        # Instance copies so vertical packs can register industry patterns
        # (IBANs, DOBs, classification markings) without touching globals.
        self._secrets = list(_SECRETS) + list(extra_secrets)
        self._pii = list(_PII) + list(extra_pii)

    def add_secret(self, label: str, pattern: re.Pattern,
                   severity: float = 1.0) -> None:
        """Decisive pattern: any match escalates toward BLOCK."""
        self._secrets.append((label, pattern, severity))

    def add_pii(self, label: str, pattern: re.Pattern,
                severity: float = 0.6) -> None:
        """Density-scored pattern: sparse hits redact, bulk dumps block."""
        self._pii.append((label, pattern, severity))

    def scan(self, output: str) -> EgressResult:
        canon = canonicalize(output)
        detections: list[Detection] = []
        redacted = output

        # Canary echo / protected-fragment leak: decisive.
        leaked = [c for c in self.canaries if c and c in output]
        leaked += [f for f in self.protected_fragments
                   if f and f in output]
        if leaked:
            detections.append(Detection(
                "egress_canary", 1.0,
                [f"protected token echoed: {leaked[0][:24]}"]))

        if _PROMPT_LEAK.search(canon):
            detections.append(Detection(
                "egress_prompt_leak", 0.9, ["system-prompt leakage markers"]))

        for label, pat, sev in self._secrets:
            hits = list(pat.finditer(output))
            if hits:
                detections.append(Detection(
                    f"egress_{label}", sev,
                    [f"{len(hits)} {label} match(es)"]))
                redacted = pat.sub(f"[REDACTED-{label}]", redacted)

        pii_total = 0.0
        for label, pat, sev in self._pii:
            hits = list(pat.finditer(output))
            if hits:
                pii_total += sev * min(len(hits), 3) / 3
                detections.append(Detection(
                    f"egress_pii_{label}", sev,
                    [f"{len(hits)} {label} match(es)"]))
                redacted = pat.sub(f"[REDACTED-{label}]", redacted)
        if pii_total > 1.2:                    # bulk PII dump = exfiltration
            detections.append(Detection(
                "egress_bulk_pii", 1.0, [f"PII density {pii_total:.2f}"]))

        # Fused score: decisive signals (canary, prompt leak, secrets, bulk
        # PII) block outright; sparse PII lands in the sanitize band so it
        # gets redacted rather than denied. Non-decisive findings carry the
        # `egress_pii_` prefix; everything else escalates on its own score.
        decisive = max((d.score for d in detections
                        if not d.detector.startswith("egress_pii_")),
                       default=0.0)
        pii_score = min(0.55, 0.3 + 0.5 * pii_total) if pii_total else 0.0
        score = max(decisive, pii_score)
        return EgressResult(score=min(score, 1.0), detections=detections,
                            redacted=redacted)
