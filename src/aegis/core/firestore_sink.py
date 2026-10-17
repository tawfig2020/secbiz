"""Firestore persistence sink (stdlib REST client, hackathon/BFSI demo tier).

Persists tamper-evident audit events and gateway verdicts to Cloud Firestore
so the deployed Cloud Run prototype keeps durable evidence across instance
restarts — Cloud Run containers are ephemeral, so local SQLite is not enough.

Design constraints (matches the rest of the core):

  * stdlib only (urllib) — zero added dependencies.
  * best-effort: writes go through a daemon-thread queue; a Firestore
    outage can never delay or break a security decision.
  * auth: on GCP the Cloud Run metadata server mints the service-account
    access token; locally the sink stays disabled (no credentials needed).

Enable with:

    AEGIS_FIRESTORE_PROJECT=<gcp project id>
    AEGIS_FIRESTORE_COLLECTION=aegis_events   (optional, default shown)
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.request
import urllib.error
from typing import Any, Mapping

log = logging.getLogger("aegis.core.firestore_sink")

_BASE = "https://firestore.googleapis.com/v1"
_METADATA_TOKEN = ("http://metadata.google.internal/computeMetadata/v1/"
                   "instance/service-accounts/default/token")


def _access_token(timeout: float = 2.0) -> str | None:
    """Mint a token from the GCP metadata server (Cloud Run / GCE).
    Returns None off-GCP so the sink disables itself cleanly."""
    try:
        req = urllib.request.Request(
            _METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())["access_token"]
    except Exception:
        return None


def _firestore_value(value: Any) -> dict[str, Any]:
    """Map a JSON-ish scalar/dict to a Firestore Value proto."""
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value[:1500]}
    if value is None:
        return {"nullValue": None}
    return {"stringValue": json.dumps(value, default=str)[:1500]}


class FirestoreSink:
    """Async, fail-open writer for security evidence documents.

    `emit(kind, fields)` is called on the request path; a single daemon
    thread drains the queue so latency-critical verdicts never wait on
    Firestore. Every failure is logged and dropped — evidence durability
    degrades, containment never does.
    """

    def __init__(self, project: str, collection: str = "aegis_events",
                 database: str = "(default)") -> None:
        self._url = (f"{_BASE}/projects/{project}/databases/{database}"
                     f"/documents/{collection}")
        self._q: queue.Queue[dict | None] = queue.Queue(maxsize=1024)
        self.enabled = False
        self._token = _access_token()
        if self._token:
            self.enabled = True
            t = threading.Thread(target=self._drain, daemon=True,
                                 name="firestore-sink")
            t.start()
            log.info("Firestore sink enabled: %s", self._url)
        else:
            log.info("Firestore sink disabled: no GCP metadata server")

    def emit(self, kind: str, fields: Mapping[str, Any]) -> None:
        """Queue one document write; never raises, never blocks callers."""
        if not self.enabled:
            return
        try:
            doc = {"fields": {"kind": {"stringValue": kind}}}
            for k, v in fields.items():
                doc["fields"][str(k)[:64]] = _firestore_value(v)
            self._q.put_nowait(doc)
        except queue.Full:
            log.warning("firestore sink queue full; dropping event")

    def _drain(self) -> None:
        while True:
            doc = self._q.get()
            if doc is None:
                return
            try:
                if self._token is None:
                    self._token = _access_token()
                    if self._token is None:
                        continue
                req = urllib.request.Request(
                    self._url,
                    data=json.dumps(doc).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self._token}",
                    },
                    method="POST")
                urllib.request.urlopen(req, timeout=5).close()
            except urllib.error.HTTPError as exc:
                if exc.code == 401:      # token expired; refresh once
                    self._token = _access_token()
                log.warning("firestore write failed: %s", exc)
            except Exception as exc:
                log.warning("firestore write failed: %s", exc)


def sink_from_env(env: Mapping[str, str] | None = None) -> FirestoreSink | None:
    """Build a sink when AEGIS_FIRESTORE_PROJECT is set; else None."""
    import os
    env = env or os.environ
    project = env.get("AEGIS_FIRESTORE_PROJECT") or env.get("AEGIS_GCP_PROJECT_ID")
    if not project or project.startswith("REPLACE_ME"):
        return None
    return FirestoreSink(
        project,
        collection=env.get("AEGIS_FIRESTORE_COLLECTION", "aegis_events"))


__all__ = ["FirestoreSink", "sink_from_env"]
