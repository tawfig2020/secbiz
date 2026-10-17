"""Usage metering + billing hook for the self-serve Solo tier.

The Solo tier is usage-priced (e.g. $X per 1k scans). This module meters
billable events (scans, action evaluations) per tenant and forwards them to
a pluggable BillingHook — the seam where Stripe metered billing or an
internal ledger attaches. No network calls here: the hook is a plain callable.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


_log = logging.getLogger(__name__)


class BillingHook(Protocol):
    """Pluggable billing sink. Implementations record usage for invoicing."""

    def record(self, tenant_id: str, event: str, units: int,
               detail: Mapping[str, Any]) -> None: ...


class InMemoryBilling:
    """Local/test billing sink: accumulates records for assertions."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, tenant_id: str, event: str, units: int,
               detail: Mapping[str, Any] | None = None) -> None:
        self.records.append({
            "tenant_id": tenant_id,
            "event": event,
            "units": units,
            "detail": dict(detail or {}),
            "ts": time.time(),
        })


@dataclass
class UsageRecord:
    tenant_id: str
    scans: int = 0
    actions: int = 0
    blocked: int = 0
    bytes_scanned: int = 0
    window_start: float = field(default_factory=time.time)

    def snapshot(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "scans": self.scans,
            "actions": self.actions,
            "blocked": self.blocked,
            "bytes_scanned": self.bytes_scanned,
            "window_start": self.window_start,
        }


class UsageMeter:
    """Per-tenant usage counters that forward billable events to a hook."""

    def __init__(self, billing: BillingHook | None = None) -> None:
        self._billing = billing
        self._usage: dict[str, UsageRecord] = {}
        self._lock = threading.Lock()

    def _get(self, tenant_id: str) -> UsageRecord:
        rec = self._usage.get(tenant_id)
        if rec is None:
            rec = UsageRecord(tenant_id=tenant_id)
            self._usage[tenant_id] = rec
        return rec

    def _bill(self, tenant_id: str, event: str, units: int,
              detail: Mapping[str, Any]) -> None:
        if self._billing is not None:
            try:
                self._billing.record(tenant_id, event, units, detail)
            except Exception:   # billing outage must not break enforcement
                _log.exception("billing hook failed for %s", tenant_id)

    def record_scan(self, tenant_id: str, payload_bytes: int,
                    blocked: bool) -> None:
        with self._lock:
            rec = self._get(tenant_id)
            rec.scans += 1
            rec.bytes_scanned += payload_bytes
            if blocked:
                rec.blocked += 1
        self._bill(tenant_id, "scan", 1,
                   {"bytes": payload_bytes, "blocked": blocked})

    def record_action(self, tenant_id: str, blocked: bool) -> None:
        with self._lock:
            rec = self._get(tenant_id)
            rec.actions += 1
            if blocked:
                rec.blocked += 1
        self._bill(tenant_id, "action", 1, {"blocked": blocked})

    def snapshot(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            return self._get(tenant_id).snapshot()

    def all_snapshots(self) -> list[dict[str, Any]]:
        with self._lock:
            return [rec.snapshot() for rec in self._usage.values()]


__all__ = [
    "BillingHook",
    "InMemoryBilling",
    "UsageMeter",
    "UsageRecord",
]
