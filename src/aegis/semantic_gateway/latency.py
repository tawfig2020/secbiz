"""Latency-budget enforcement for the semantic gateway.

Vertical packs declare `latency_budget_ms` in their metadata; before this
module the value was informational only — a healthcare deployment with a
200 ms budget could silently serve a 400 ms scan, which in a clinical
workflow is worse than no answer at all.

Policies per vertical (wired by VerticalPack.configure_gateway):

  fail_closed          -> verdict becomes BLOCK (healthcare: a late
                          clinical decision is worse than a blocked one)
  degrade_to_fast_path -> re-fuse on rules-only detectors only, letting
                          the transaction proceed if the fast path is
                          clean (BFSI payments continuity)
  alert_only           -> keep the verdict, emit a breach event
                          (government: mission continuity)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LatencyPolicy(str, Enum):
    FAIL_CLOSED = "fail_closed"
    DEGRADE_TO_FAST_PATH = "degrade_to_fast_path"
    ALERT_ONLY = "alert_only"


@dataclass(frozen=True)
class LatencyBudget:
    budget_ms: float
    policy: LatencyPolicy = LatencyPolicy.ALERT_ONLY


# Detectors considered the "fast path": pure rules, no learned/semantic
# scoring. Names match Detection.detector values.
FAST_PATH_DETECTORS = frozenset({
    "local_sequence_alignment",
    "deception_canary",
    "taint_tracker",
    "boundary_guard",
})
