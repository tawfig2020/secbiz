"""Durable, append-only storage for signed attestations (SQLite).

Attestations are the regulator-facing proof that containment happened; an
in-memory list loses them on restart. This store only ever INSERTs. Each row
is independently verifiable with the signing key/public key, so storage
tampering is detected by verify_attestation, not trusted.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .attestation import Attestation

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id TEXT NOT NULL,
    action      TEXT NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    params_digest TEXT NOT NULL,
    nonce       TEXT NOT NULL UNIQUE,
    ts          REAL NOT NULL,
    signature   TEXT NOT NULL
);
"""


class AttestationStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(_SCHEMA)
        self._db.commit()
        self._lock = threading.Lock()

    def append(self, att: Attestation) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO attestations (contract_id, action, decision,"
                " reason, subject, params_digest, nonce, ts, signature)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (att.contract_id, att.action, att.decision, att.reason,
                 att.subject, att.params_digest, att.nonce, att.ts,
                 att.signature))
            self._db.commit()

    def load(self) -> list[Attestation]:
        with self._lock:
            rows = self._db.execute(
                "SELECT contract_id, action, decision, reason, subject,"
                " params_digest, nonce, ts, signature FROM attestations"
                " ORDER BY seq").fetchall()
        return [Attestation(*r) for r in rows]

    def close(self) -> None:
        self._db.close()


__all__ = ["AttestationStore"]
