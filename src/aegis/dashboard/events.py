"""Dashboard event plane: the single stream all three views read from.

Every security-relevant happening — gateway scans, egress scans, contract
decisions, HARD cycle phases, intel-feed ingestion — is emitted onto an
EventBus as a DashboardEvent. The bus is a bounded ring buffer with
subscribers, so a live UI (WebSocket), the CLI demo, and tests can all
consume the same stream.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

# Event kinds ----------------------------------------------------------
KIND_SCAN = "scan"                    # inbound gateway verdict
KIND_EGRESS = "egress_scan"           # outbound scan verdict
KIND_CONTRACT = "contract_decision"   # reference-monitor decision
KIND_HARD = "hard"                    # self-improvement phase event
KIND_INTEL = "intel"                  # threat-feed ingestion
KIND_SOC = "soc"                      # red/blue loop event


@dataclass(frozen=True)
class DashboardEvent:
    ts_ms: float
    kind: str
    actor: str                        # "gateway", "reference_monitor", "hard"...
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


Subscriber = Callable[[DashboardEvent], None]


class EventBus:
    """Bounded in-memory event stream with subscriptions (fail-silent)."""

    def __init__(self, maxlen: int = 2000, clock=time.time) -> None:
        self._events: deque[DashboardEvent] = deque(maxlen=maxlen)
        self._subs: list[Subscriber] = []
        self._clock = clock
        self._lock = threading.Lock()

    def emit(self, kind: str, actor: str, summary: str,
             **data: Any) -> DashboardEvent:
        ev = DashboardEvent(ts_ms=self._clock() * 1000.0,
                            kind=kind, actor=actor,
                            summary=summary, data=dict(data))
        with self._lock:
            self._events.append(ev)
            subs = list(self._subs)
        for sub in subs:
            try:
                sub(ev)
            except Exception:        # a broken subscriber must never
                pass                 # break the security pipeline
        return ev

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subs.append(fn)

    def events(self, kind: str | None = None) -> list[DashboardEvent]:
        with self._lock:
            snapshot = list(self._events)
        if kind is None:
            return snapshot
        return [e for e in snapshot if e.kind == kind]

    def replay(self, kind: str | None = None) -> Iterator[DashboardEvent]:
        yield from self.events(kind)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)
