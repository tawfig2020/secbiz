"""Semantic classifier (Pillar 2 fusion head).

HeuristicClassifier is the stdlib default: fail-closed fusion where any
high-confidence detector blocks, plus corroboration bonus when multiple
weak detectors agree.

GeminiClassifier is the Vertex AI adapter point (Gemini 2.5 Flash per spec
section 5.2). It is optional: without a client the gateway falls back to the
heuristic head, so the pipeline never depends on a model's judgment for
safety.
"""
from __future__ import annotations

import math
from typing import Protocol

from .detectors.base import Detection


class Classifier(Protocol):
    def fuse(self, detections: list[Detection]) -> float:
        """Return fused maliciousness score 0..1."""


class HeuristicClassifier:
    """Fail-closed fusion: max detector score, plus corroboration."""

    name = "heuristic"

    def fuse(self, detections: list[Detection]) -> float:
        if not detections:
            return 0.0
        top = max(d.score for d in detections)
        corroborating = sum(1 for d in detections if d.score >= 0.4)
        if corroborating >= 2:
            top = min(1.0, top + 0.1)
        return top


class GeminiClassifier:
    """Adapter for a fine-tuned Gemini Flash judge on Vertex AI.

    The client is any object exposing `score(text, detections) -> float`
    (e.g. a thin wrapper over vertexai.generative_models). When no client
    is configured the classifier is inert and the heuristic head decides --
    safety-critical fusion never blocks on model availability.
    """

    name = "gemini-flash"
    wants_text = True        # gateway passes the payload to fuse()

    def __init__(self, client=None, model: str = "gemini-2.5-flash") -> None:
        self.client = client
        self.model = model
        self._fallback = HeuristicClassifier()

    def fuse(self, detections: list[Detection], text: str = "") -> float:
        heuristic = self._fallback.fuse(detections)
        if self.client is None:
            return heuristic
        try:
            model_score = float(self.client.score(text, detections))
        except Exception:
            return heuristic                     # heuristic head decides
        if math.isnan(model_score):
            return heuristic
        model_score = min(1.0, max(0.0, model_score))
        # Model refines but never overrides a confident heuristic block.
        return max(heuristic, model_score)
