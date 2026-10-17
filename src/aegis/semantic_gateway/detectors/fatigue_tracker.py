"""Fatigue tracker (cross-domain: behavioral analytics).

Agentic attackers probe repeatedly, mutating payloads until one slips
through -- a low-and-slow campaign that per-payload detectors cannot see.
This detector keeps a sliding window of scan attempts per source_id and
escalates its score as anomalous attempts accumulate.

MVP detector #3 of 3 (spec section 5.1).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque

from .base import Detection, ScanContext


class FatigueTrackerDetector:
    name = "fatigue_tracker"

    def __init__(self, window_seconds: float = 60.0,
                 escalation_at: int = 4,
                 max_sources: int = 10_000) -> None:
        self.window = window_seconds
        self.escalation_at = escalation_at
        self.max_sources = max_sources
        # source_id -> deque of (timestamp, was_flagged); LRU-bounded.
        self._events: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.Lock()

    def observe(self, source_id: str, flagged: bool,
                now: float | None = None) -> None:
        """Called by the gateway after every scan (external observation)."""
        now = time.time() if now is None else now
        with self._lock:
            dq = self._events.get(source_id)
            if dq is None:
                dq = self._events[source_id] = deque()
                while len(self._events) > self.max_sources:
                    self._events.popitem(last=False)
            else:
                self._events.move_to_end(source_id)
            dq.append((now, flagged))
            cutoff = now - self.window
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        now = time.time()
        with self._lock:
            dq = self._events.get(ctx.source_id)
            if not dq:
                return Detection(self.name, 0.0)
            cutoff = now - self.window
            recent = [e for e in dq if e[0] >= cutoff]
        flagged = sum(1 for _, f in recent if f)
        if len(recent) < self.escalation_at and flagged < 2:
            return Detection(self.name, 0.0)
        # Score grows with volume and prior suspicion in the window.
        score = min(1.0, 0.25 * flagged + 0.08 * len(recent))
        ev = [f"{len(recent)} scans/{flagged} flagged from "
              f"{ctx.source_id} within {self.window:.0f}s"]
        return Detection(self.name, score if score >= 0.3 else 0.0, ev)

    def reset(self, source_id: str | None = None) -> None:
        with self._lock:
            if source_id is None:
                self._events.clear()
            else:
                self._events.pop(source_id, None)
