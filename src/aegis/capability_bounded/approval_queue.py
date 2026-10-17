"""Durable human-approval queue: gives DEFER_HUMAN a consumer.

Before this, a `requires_human_approval` action was deferred and then
vanished — deferred work had nowhere to go. `ApprovalQueue` persists
deferred decisions to SQLite, exposes approve/deny resolution, mints a
resolution attestation (the human's decision is part of the evidence
chain), and streams `approval_request` / `approval_resolved` events.

Attach to the monitor:

    queue = ApprovalQueue("data/approvals.db", event_bus=bus)
    mon = ReferenceMonitor(contracts, audit, approval_queue=queue)

Every DEFER_HUMAN decision is then automatically enqueued.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid import cycle; only used for typing
    from .reference_monitor import Action, Context

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    params      TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    subject     TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    approver    TEXT,
    created_at  REAL NOT NULL,
    resolved_at REAL,
    resolution_signature TEXT
);
"""


@dataclass(frozen=True)
class ApprovalItem:
    id: str
    action: str
    params: dict[str, Any]
    contract_id: str
    subject: str
    reason: str
    status: str                      # pending | approved | denied
    approver: str
    created_at: float
    resolved_at: float | None
    resolution_signature: str


class ApprovalQueue:
    """SQLite-backed queue; safe for concurrent readers via check_same_thread
    + a write lock. `signer` mints resolution attestations — pass the
    monitor's signer so a single trust domain signs the whole chain."""

    def __init__(self, path: str | Path = ":memory:", *, signer=None,
                 event_bus=None) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(_SCHEMA)
        self._db.commit()
        self._lock = threading.Lock()
        self._signer = signer
        self._bus = event_bus

    # -- producer ----------------------------------------------------------
    def enqueue(self, action: "Action", context: "Context",
                reason: str) -> str:
        """Persist a deferred action; returns the approval id."""
        approval_id = secrets.token_hex(8)
        with self._lock:
            self._db.execute(
                "INSERT INTO approvals (id, action, params, contract_id,"
                " subject, reason, status, created_at)"
                " VALUES (?,?,?,?,?,?,'pending',?)",
                (approval_id, action.name,
                 json.dumps(action.params, default=str),
                 context.contract_id, context.subject, reason,
                 time.time()))
            self._db.commit()
        self._emit("approval_request",
                   f"{action.name} awaiting approval "
                   f"[{approval_id}]",
                   approval_id=approval_id, action=action.name,
                   contract_id=context.contract_id)
        return approval_id

    # -- consumer ----------------------------------------------------------
    def pending(self) -> list[ApprovalItem]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM approvals WHERE status='pending'"
                " ORDER BY created_at").fetchall()
        return [self._row(r) for r in rows]

    def get(self, approval_id: str) -> ApprovalItem | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM approvals WHERE id=?",
                (approval_id,)).fetchone()
        return self._row(row) if row else None

    def approve(self, approval_id: str, approver: str) -> ApprovalItem:
        return self._resolve(approval_id, approver, "approved")

    def deny(self, approval_id: str, approver: str) -> ApprovalItem:
        return self._resolve(approval_id, approver, "denied")

    def _resolve(self, approval_id: str, approver: str,
                 status: str) -> ApprovalItem:
        item = self.get(approval_id)
        if item is None:
            raise KeyError(f"unknown approval id {approval_id!r}")
        if item.status != "pending":
            raise ValueError(f"approval {approval_id!r} already {item.status}")
        if not approver or approver == item.subject:
            # Four-eyes: the requesting subject can never resolve its own
            # deferred action.
            raise PermissionError(
                "separation of duties: approver must be a distinct, "
                "non-empty identity from the requesting subject")

        sig = ""
        if self._signer is not None:
            from aegis.core.attestation import sign_attestation
            att = sign_attestation(
                signer=self._signer, contract_id=item.contract_id,
                action=item.action,
                decision="APPROVED" if status == "approved" else "DENIED",
                reason=item.reason, subject=approver,
                params={"approval_id": approval_id})
            sig = att.signature

        with self._lock:
            cur = self._db.execute(
                "UPDATE approvals SET status=?, approver=?, resolved_at=?,"
                " resolution_signature=? WHERE id=? AND status='pending'",
                (status, approver, time.time(), sig, approval_id))
            self._db.commit()
            won = cur.rowcount == 1
        if not won:                      # lost a race with another resolver
            raise ValueError(f"approval {approval_id!r} already resolved")
        resolved = self.get(approval_id)
        self._emit("approval_resolved",
                   f"{item.action} {status} by {approver}",
                   approval_id=approval_id, action=item.action,
                   status=status, approver=approver,
                   resolution_signature=sig[:16])
        return resolved  # type: ignore[return-value]

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _row(row) -> ApprovalItem:
        (i, action, params, cid, subj, reason, status, approver,
         created, resolved, sig) = row
        return ApprovalItem(
            id=i, action=action, params=json.loads(params),
            contract_id=cid, subject=subj, reason=reason, status=status,
            approver=approver or "", created_at=created,
            resolved_at=resolved, resolution_signature=sig or "")

    def _emit(self, kind: str, summary: str, **data) -> None:
        if self._bus is not None:
            try:
                self._bus.emit(kind, "approval_queue", summary, **data)
            except Exception:
                pass

    def close(self) -> None:
        self._db.close()
