"""Multi-turn escalation detector (cross-domain: behavioral session analysis).

Single-turn scans miss slow-burn attacks: grooming turns that establish
rapport, priming turns that plant persistent instructions ("remember this",
"from now on"), then a strike turn whose text alone looks mild. This
detector keeps per-source session state and fires on:
  - priming markers (persistent-instruction attempts)
  - escalation delta: instruction density jumps vs the session baseline
  - grooming pattern: repeated priming followed by directive content
"""
from __future__ import annotations

import re
import statistics
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from .base import (
    IMPERATIVE,
    Detection,
    ScanContext,
    instruction_density,
    sentences,
)

_PRIMING = re.compile(
    r"\b(remember\s+(this|that|when|these)|from\s+now\s+on|going\s+forward|"
    r"as\s+(we|i)\s+(discussed|agreed|said|established)|"
    r"earlier\s+(i|we)\s+(told|said|agreed|instructed)|"
    r"you\s+(promised|agreed|confirmed)|"
    r"our\s+(previous|earlier)\s+(conversation|agreement|instructions?)|"
    r"store\s+(this|these)\s+(instruction|rule|fact)|"
    r"update\s+your\s+(rules|instructions|memory|guidelines))\b",
    re.IGNORECASE)


@dataclass
class _Session:
    densities: deque = field(default_factory=lambda: deque(maxlen=12))
    priming_hits: int = 0
    last_seen: float = field(default_factory=time.monotonic)


class MultiTurnEscalationDetector:
    name = "multi_turn_escalation"

    def __init__(self, min_turns: int = 3,
                 escalation_delta: float = 0.35,
                 max_sessions: int = 10_000,
                 session_ttl: float = 1800.0) -> None:
        self.min_turns = min_turns
        self.escalation_delta = escalation_delta
        self.max_sessions = max_sessions
        self.session_ttl = session_ttl
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    def _session(self, source_id: str) -> _Session:
        now = time.monotonic()
        with self._lock:
            st = self._sessions.get(source_id)
            if st is not None and now - st.last_seen > self.session_ttl:
                st = None                       # idle session expired
            if st is None:
                st = _Session(last_seen=now)
                self._sessions[source_id] = st
                while len(self._sessions) > self.max_sessions:
                    self._sessions.popitem(last=False)
            st.last_seen = now
            self._sessions.move_to_end(source_id)
            return st

    def reset(self, source_id: str | None = None) -> None:
        with self._lock:
            if source_id is None:
                self._sessions.clear()
            else:
                self._sessions.pop(source_id, None)

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        st = self._session(ctx.source_id)
        canon = ctx.canonical or text
        cur = max((instruction_density(s) for s in sentences(canon)),
                  default=0.0)
        primed = bool(_PRIMING.search(canon))

        score, evidence = 0.0, []
        if primed:
            st.priming_hits += 1
            if st.priming_hits >= 2:
                score += 0.5
                evidence.append(
                    f"repeated priming attempts ({st.priming_hits})")
            else:
                score += 0.2
                evidence.append("persistent-instruction marker")

        hist = list(st.densities)
        if len(hist) >= self.min_turns and cur >= 0.5:
            if cur - statistics.fmean(hist) >= self.escalation_delta:
                score += 0.6
                evidence.append(
                    f"instruction-density spike {cur:.2f} vs session "
                    f"baseline {statistics.fmean(hist):.2f}")
        if st.priming_hits >= 1 and cur >= 0.5:
            score += 0.3
            evidence.append("priming followed by directive content")

        # Soft strike: imperative verb without agent-target words is too
        # vague to trip single-turn detectors, but a directive arriving
        # after several grooming turns is the classic slow-burn strike.
        if len(hist) >= self.min_turns - 1 and cur < 0.5:
            if IMPERATIVE.search(canon):
                score += 0.35
                evidence.append("directive turn after session grooming")

        st.densities.append(cur)
        return Detection(self.name, min(score, 1.0), evidence)
