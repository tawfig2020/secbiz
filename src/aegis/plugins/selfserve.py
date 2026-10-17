"""Self-serve Starter API for the Solo tier (Phase 2).

Wraps a resolved Solo plugin with API-key issuance, usage metering, and a
billing hook, exposed over a dependency-free stdlib HTTP server:

    POST /signup            -> issue an API key
    POST /scan              -> gateway scan (metered)
    POST /evaluate_action   -> contract decision (metered)
    GET  /usage?api_key=..  -> per-key usage summary
    GET  /healthz           -> liveness

Authentication is a bearer-style `api_key` in the JSON body (or query string
for /usage). Invalid keys fail closed with 401 before any metering happens.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from ..edge import ModuleVerdict
from .metering import UsageMeter
from .registry import ResolvedPlugin


MAX_BODY_BYTES = 1_000_000
MAX_EMAIL_LEN = 254


class TenantLimitExceeded(ValueError):
    """Raised when the service cannot accept more tenants."""


def _key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


@dataclass
class Tenant:
    key_hash: str            # sha256 of the API key; plaintext is never kept
    plan: str
    email: str
    created_at: float


class StarterService:
    """API-key + metering facade over a resolved Solo plugin."""

    def __init__(self, plugin: ResolvedPlugin,
                 meter: UsageMeter | None = None,
                 max_tenants: int = 100_000) -> None:
        self.plugin = plugin
        self.meter = meter or UsageMeter()
        self.max_tenants = max_tenants
        self._tenants: dict[str, Tenant] = {}     # key_hash -> Tenant
        self._lock = threading.Lock()

    # -- tenant management ------------------------------------------------
    def issue_key(self, plan: str = "solo", email: str = "") -> dict[str, Any]:
        key = "aegis_" + secrets.token_hex(16)
        digest = _key_hash(key)
        with self._lock:
            if len(self._tenants) >= self.max_tenants:
                raise TenantLimitExceeded("tenant capacity reached")
            self._tenants[digest] = Tenant(digest, plan, email, time.time())
        return {"api_key": key, "tier": self.plugin.tier.id, "plan": plan}

    def authenticate(self, api_key: str) -> bool:
        if not isinstance(api_key, str) or not api_key:
            return False
        with self._lock:
            return _key_hash(api_key) in self._tenants

    def _tenant_id(self, api_key: str) -> str:
        # Unique per key: two signups sharing an email must not share usage,
        # rate-limit or fatigue state (cross-tenant poisoning).
        return "t_" + _key_hash(api_key)[:16]

    # -- metered operations ----------------------------------------------
    def scan(self, api_key: str, payload: str) -> ModuleVerdict:
        tenant = self._tenant_id(api_key)
        verdict = self.plugin.module.inspect_request(payload, source_id=tenant)
        self.meter.record_scan(
            tenant, len(payload.encode("utf-8", "replace")),
            verdict.verdict != "ALLOW")
        return verdict

    def evaluate_action(self, api_key: str, action: str, contract_id: str,
                        params: Mapping[str, Any] | None = None) -> ModuleVerdict:
        tenant = self._tenant_id(api_key)
        verdict = self.plugin.module.evaluate_action(
            action, contract_id, params, source_id=tenant)
        self.meter.record_action(tenant, verdict.verdict != "ALLOW")
        return verdict

    def usage(self, api_key: str) -> dict[str, Any]:
        return self.meter.snapshot(self._tenant_id(api_key))


# ------------------------------------------------------------- HTTP adapter
def make_handler(service: StarterService):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, body: Mapping[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict | None:
            """Parsed JSON object, or None if invalid / too large."""
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if n < 0 or n > MAX_BODY_BYTES:
                return None
            raw = self.rfile.read(n) if n else b"{}"
            try:
                body = json.loads(raw.decode() or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            return body if isinstance(body, dict) else None

        def _bearer(self) -> str:
            auth = self.headers.get("Authorization", "")
            return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

        def _require_key(self, body: Mapping[str, Any]) -> str | None:
            key = self._bearer() or body.get("api_key", "")
            if not service.authenticate(key):
                self._json(401, {"error": "invalid or missing api_key"})
                return None
            return key

        def do_POST(self):                      # noqa: N802 (stdlib API)
            body = self._body()
            if body is None:
                return self._json(400, {"error": "invalid or oversized JSON"})
            if self.path == "/signup":
                plan = body.get("plan", "solo")
                email = body.get("email", "")
                if (not isinstance(plan, str) or not isinstance(email, str)
                        or len(email) > MAX_EMAIL_LEN or len(plan) > 32):
                    return self._json(400, {"error": "invalid plan/email"})
                try:
                    return self._json(201, service.issue_key(plan, email))
                except TenantLimitExceeded:
                    return self._json(429, {"error": "capacity reached"})
            key = self._require_key(body)
            if key is None:
                return
            if self.path == "/scan":
                payload = body.get("payload", "")
                if not isinstance(payload, str):
                    return self._json(400, {"error": "payload must be a string"})
                v = service.scan(key, payload)
                return self._json(200, v.to_dict())
            if self.path == "/evaluate_action":
                action = body.get("action", "")
                contract_id = body.get("contract_id", "")
                params = body.get("params")
                if (not isinstance(action, str)
                        or not isinstance(contract_id, str)
                        or not (params is None or isinstance(params, dict))):
                    return self._json(400, {"error": "invalid action request"})
                v = service.evaluate_action(key, action, contract_id, params)
                return self._json(200, v.to_dict())
            self._json(404, {"error": "unknown endpoint"})

        def do_GET(self):                       # noqa: N802
            if self.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if self.path.startswith("/usage"):
                qs = parse_qs(urlparse(self.path).query)
                key = self._bearer() or (qs.get("api_key") or [""])[0]
                if not service.authenticate(key):
                    return self._json(401, {"error": "invalid or missing api_key"})
                return self._json(200, service.usage(key))
            self._json(404, {"error": "unknown endpoint"})

        def log_message(self, fmt, *args):      # quiet stdlib logging
            return

    return Handler


def serve_http(service: StarterService, host: str = "127.0.0.1",
               port: int = 8089) -> ThreadingHTTPServer:
    """Start a stdlib HTTP server exposing the Starter API. Caller manages it."""
    server = ThreadingHTTPServer((host, port), make_handler(service))
    server.daemon_threads = True
    return server


__all__ = [
    "StarterService",
    "Tenant",
    "TenantLimitExceeded",
    "make_handler",
    "serve_http",
]
