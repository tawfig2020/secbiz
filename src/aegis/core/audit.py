"""Append-only, hash-chained audit log.

Regulatory traceability (DORA, HIPAA Security Rule, EU AI Act) requires every
security-relevant decision to be explainable and tamper-evident. Each event
embeds the hash of its predecessor, so retroactive modification breaks the
chain and is detected by verify().
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class AuditEvent:
    seq: int
    timestamp: float
    actor: str
    event: str
    detail: dict
    prev_hash: str
    hash: str = ""

    def compute_hash(self) -> str:
        body = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "event": self.event,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(_canonical(body).encode()).hexdigest()


class AuditLog:
    """Hash-chained log. In-memory by default; pass `path` for a durable
    SQLite store. A persisted log is re-verified on load and refuses to
    open if the stored chain was tampered with."""

    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._head = self.GENESIS
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        if path is not None:
            self._db = sqlite3.connect(str(path), check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY,"
                " timestamp REAL NOT NULL, actor TEXT NOT NULL,"
                " event TEXT NOT NULL, detail TEXT NOT NULL,"
                " prev_hash TEXT NOT NULL, hash TEXT NOT NULL)")
            self._db.commit()
            self._load()

    def _load(self) -> None:
        rows = self._db.execute(
            "SELECT seq, timestamp, actor, event, detail, prev_hash, hash"
            " FROM audit ORDER BY seq").fetchall()
        for seq, ts, actor, event, detail, prev, h in rows:
            self._events.append(AuditEvent(seq, ts, actor, event,
                                           json.loads(detail), prev, h))
        if not self.verify():
            self._events.clear()
            self.close()
            raise ValueError("persisted audit log failed integrity check")
        if self._events:
            self._head = self._events[-1].hash

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def record(self, actor: str, event: str, detail: dict | None = None) -> AuditEvent:
        with self._lock:
            ev = AuditEvent(
                seq=len(self._events),
                timestamp=time.time(),
                actor=actor,
                event=event,
                detail=detail or {},
                prev_hash=self._head,
            )
            ev.hash = ev.compute_hash()
            if self._db is not None:       # durable first, then in-memory
                self._db.execute(
                    "INSERT INTO audit VALUES (?,?,?,?,?,?,?)",
                    (ev.seq, ev.timestamp, ev.actor, ev.event,
                     _canonical(ev.detail), ev.prev_hash, ev.hash))
                self._db.commit()
            self._events.append(ev)
            self._head = ev.hash
            return ev

    def verify(self) -> bool:
        prev = self.GENESIS
        for i, ev in enumerate(self._events):
            if ev.seq != i or ev.prev_hash != prev or ev.hash != ev.compute_hash():
                return False
            prev = ev.hash
        return True

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def render(self) -> str:
        return "\n".join(_canonical(vars(ev)) for ev in self._events)
