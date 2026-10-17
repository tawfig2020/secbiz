"""Failure trace analyzer (HARD phase 2: Analyze).

Clusters bypassed scenarios and extracts candidate signature phrases:
token n-grams that recur across bypassed attacks but rarely appear in
benign traffic. These become candidate evolution artifacts for the
local-sequence-alignment detector.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "of", "to", "for", "is", "in", "on",
         "by", "with", "this", "that", "it", "attached", "document",
         "end", "of"}


@dataclass(frozen=True)
class AnalysisReport:
    bypass_clusters: dict[str, int]          # category -> count
    weakest_detectors: dict[str, int]        # detector -> times absent/low
    candidate_phrases: list[str]


class FailureTraceAnalyzer:
    def __init__(self, ngram: int = 3, min_support: int = 2) -> None:
        self.ngram = ngram
        self.min_support = min_support

    def analyze(self, traces: list[dict],
                benign_payloads: list[str] | None = None) -> AnalysisReport:
        bypasses = [t for t in traces if t.get("kind", "bypass") == "bypass"]

        clusters: Counter[str] = Counter(t["category"] for t in bypasses)

        weak: Counter[str] = Counter()
        for t in bypasses:
            scores = t.get("detector_scores", {})
            for det in ("local_sequence_alignment", "stylometric_analyzer",
                        "taint_tracker", "mechanism_design",
                        "spectral_signal", "deception_canary"):
                if scores.get(det, 0.0) < 0.4:
                    weak[det] += 1

        benign_grams = self._gram_set(benign_payloads or [])
        gram_freq: Counter[str] = Counter()
        for t in bypasses:
            gram_freq.update(self._grams(t["payload"]))

        candidates = [
            g for g, n in gram_freq.most_common()
            if n >= self.min_support and g not in benign_grams
        ]
        return AnalysisReport(
            bypass_clusters=dict(clusters),
            weakest_detectors=dict(weak),
            candidate_phrases=candidates[:10],
        )

    # -- n-gram helpers ----------------------------------------------------
    def _grams(self, text: str) -> list[str]:
        toks = [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]
        return [" ".join(toks[i:i + self.ngram])
                for i in range(len(toks) - self.ngram + 1)]

    def _gram_set(self, texts: list[str]) -> set[str]:
        out: set[str] = set()
        for t in texts:
            out.update(self._grams(t))
        return out
