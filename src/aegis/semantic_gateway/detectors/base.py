"""Detector interface and shared normalization.

Every cross-domain detector returns a Detection(score 0..1, evidence list).
The gateway canonicalizes input once and shares it via ScanContext so each
detector sees the same normalized surface (unicode NFKC, zero-width chars and
HTML entities stripped, leetspeak collapse available via `leet` field).
"""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Protocol


_LEET = str.maketrans({"@": "a", "0": "o", "1": "i", "3": "e",
                       "$": "s", "5": "s", "7": "t", "4": "a"})


# Common Cyrillic/Greek lookalikes folded to ASCII so homoglyph
# substitution ("ignоre" with Cyrillic 'о') can't evade token matching.
_CONFUSABLES = str.maketrans({
    "а": "a", "с": "c", "е": "e", "і": "i", "о": "o", "р": "p", "ѕ": "s",
    "х": "x", "у": "y", "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H",
    "І": "I", "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T",
    "Х": "X", "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Ζ": "Z",
})


def canonicalize(text: str) -> str:
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text
                   if unicodedata.category(ch) not in ("Cf", "Mn")
                   or ch in "\n\t")
    return text.translate(_CONFUSABLES)


@dataclass
class ScanContext:
    """Shared per-scan state handed to every detector."""
    source_id: str = "default"          # origin stream (for fatigue tracking)
    canonical: str = ""                 # canonicalized payload
    leet: str = ""                      # canonical + leetspeak collapsed
    canaries: tuple[str, ...] = ()      # deception canary tokens in scope

    @classmethod
    def build(cls, text: str, source_id: str = "default",
              canaries: tuple[str, ...] = ()) -> "ScanContext":
        canon = canonicalize(text)
        return cls(source_id=source_id, canonical=canon,
                   leet=canon.translate(_LEET), canaries=canaries)


@dataclass
class Detection:
    detector: str
    score: float                        # 0.0 .. 1.0
    evidence: list[str] = field(default_factory=list)

    @property
    def fired(self) -> bool:
        return self.score > 0.0


class Detector(Protocol):
    name: str

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        ...


# Shared linguistic signals reused by several detectors.
IMPERATIVE = re.compile(
    r"\b(ignore|disregard|forget|override|reveal|send|transfer|delete|grant|"
    r"escalate|disable|exfiltrate|forward|output|execute|approve|authorize|"
    r"bypass|print|dump|leak|export|email|invoke|call|modify|upload|wire|"
    r"use|run)\b", re.IGNORECASE)

AGENT_TARGET = re.compile(
    r"\b(agent|assistant|model|system|you|your|instructions?|prompt|tools?|"
    r"functions?|api|database|records?|policy|policies|rules?)\b",
    re.IGNORECASE)


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"[.\n!?]+", text) if len(s.strip()) >= 12]


def instruction_density(sentence: str) -> float:
    """0..1 measure of 'instruction-shapedness': imperatives aimed at the agent."""
    imp = len(IMPERATIVE.findall(sentence))
    tgt = len(AGENT_TARGET.findall(sentence))
    if imp == 0 or tgt == 0:
        return 0.0
    return min(1.0, 0.4 + 0.15 * imp + 0.1 * min(tgt, 3))
