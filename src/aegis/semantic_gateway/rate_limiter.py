"""Boundary guard: payload size cap + sliding-window rate limiting.

The gateway itself is attack surface: an adversary can flood it to exhaust
detector CPU budgets or queue-bomb downstream agents, or send oversized
payloads to inflate scan latency past the 5ms budget. Fail closed: over the
limit or over the size cap -> BLOCK before any detector runs.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    reason: str = ""


class RateLimiter:
    """Sliding-window limiter: per-source and global request budgets."""

    def __init__(self, per_source_max: int = 120,
                 window_seconds: float = 60.0,
                 global_max: int = 5000,
                 max_sources: int = 10_000) -> None:
        self.per_source_max = per_source_max
        self.window = window_seconds
        self.global_max = global_max
        self.max_sources = max_sources
        # LRU table: unbounded growth under unique-source flooding is a DoS.
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        # Kept apart from per-source keys so a client-chosen source_id can
        # never alias or reset the global budget.
        self._global: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, q: deque[float], now: float) -> None:
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()

    def allow(self, source_id: str, now: float | None = None) -> LimitResult:
        now = time.monotonic() if now is None else now
        with self._lock:
            glob = self._global
            self._prune(glob, now)
            if len(glob) >= self.global_max:
                return LimitResult(False, "global rate limit exceeded")
            src = self._hits.get(source_id)
            if src is None:
                src = self._hits[source_id] = deque()
                while len(self._hits) > self.max_sources:
                    self._hits.popitem(last=False)      # evict LRU source
            else:
                self._hits.move_to_end(source_id)
            self._prune(src, now)
            if len(src) >= self.per_source_max:
                return LimitResult(
                    False, f"source {source_id!r} rate limit exceeded")
            src.append(now)
            glob.append(now)
            return LimitResult(True)
