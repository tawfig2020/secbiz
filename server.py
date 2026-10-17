"""Aegis Command Center & Web Server (Stdlib Only)
Serves the enterprise front-end and connects directly to the Aegis
Pillars: Semantic Gateway, Reference Monitor, Approval Queue, and HARD.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import secrets
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent

from aegis.capability_bounded import (
    Action,
    Context,
    ReferenceMonitor,
)
from aegis.core import (
    AttestationStore,
    AuditLog,
    default_signer,
    rate_limiter_from_env,
    sign_attestation,
)
from aegis.core.firestore_sink import sink_from_env
from aegis.dashboard import EventBus
from aegis.semantic_gateway import SemanticGateway
from aegis.semantic_gateway.classifier import GeminiClassifier
from aegis.semantic_gateway.gemini_client import client_from_env
from aegis.semantic_gateway.rate_limiter import RateLimiter
from aegis.verticals import bfsi_pack, healthcare_pack

log = logging.getLogger("aegis.server")

WEB_DIR = (ROOT / "web").resolve()
MAX_BODY_BYTES = 1_000_000
MAX_LABEL_LEN = 128
SOCKET_TIMEOUT_S = 15           # caps slow-loris style connections

# --- authentication (Risk A) ---------------------------------------------
# API keys come from AEGIS_API_KEYS (comma separated). Only SHA-256 digests
# are kept in memory. With no keys configured the server is in open DEV mode
# and run_server() refuses to bind a non-loopback interface.
_AUTH_DIGESTS: tuple[bytes, ...] = ()
_TRUST_PROXY = os.environ.get("AEGIS_TRUST_PROXY") == "1"
# Public demo mode (hackathon deployments): allows binding a non-loopback
# interface without API keys. Per-IP HTTP rate limiting still applies.
_PUBLIC_DEMO = os.environ.get("AEGIS_PUBLIC_DEMO") == "1"


def _digest(key: str) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()


def configure_auth(keys: Iterable[str]) -> None:
    """Install the accepted API keys (empty = open dev mode)."""
    global _AUTH_DIGESTS
    _AUTH_DIGESTS = tuple(_digest(k) for k in keys if k)


def _is_authorized(presented: str) -> bool:
    if not _AUTH_DIGESTS:
        return True                          # open dev mode
    d = _digest(presented or "")
    ok = False
    for known in _AUTH_DIGESTS:              # no early exit: constant time
        ok |= hmac.compare_digest(known, d)
    return ok


configure_auth((os.environ.get("AEGIS_API_KEYS") or "").split(","))

# Per-client HTTP rate limit (Risk E), independent of the gateway limiter.
_http_limiter = RateLimiter(per_source_max=600, window_seconds=60.0,
                            global_max=20_000)

# Signing key: supplied via AEGIS_SIGNING_KEY, else a random per-process key.
# Never hard-code key material in source.
_SIGNING_KEY = (os.environ.get("AEGIS_SIGNING_KEY") or
                secrets.token_hex(32)).encode("utf-8")

# Attestation signer: Ed25519 (asymmetric) by default so auditors hold only
# the public key and cannot forge proofs. Falls back to HMAC when the
# optional `cryptography` package is absent. The HMAC `_SIGNING_KEY` remains
# the symmetric key for single-use capability tokens (self-verified).
_signer = default_signer()

# Initialize global engine components
_bus = EventBus()
# Optional Gemini judge (AEGIS_GEMINI_API_KEY): refines the heuristic head;
# a fooled or offline judge can only make verdicts stricter, never weaker.
_gemini_client = client_from_env()
_classifier = (GeminiClassifier(client=_gemini_client)
               if _gemini_client is not None else None)
_gw = SemanticGateway(event_bus=_bus, rate_limiter=rate_limiter_from_env(),
                      classifier=_classifier)
# Optional Firestore evidence sink (AEGIS_FIRESTORE_PROJECT): async,
# fail-open — evidence durability degrades, containment never does.
_sink = sink_from_env()
_health = healthcare_pack()
_bfsi = bfsi_pack()

_health.configure_gateway(_gw)
_bfsi.configure_gateway(_gw)   # installs SwiftManipulationDetector + IBAN egress

# Durable evidence: set AEGIS_DATA_DIR to persist the audit chain and
# attestations across restarts (otherwise in-memory, dev only).
_DATA_DIR = os.environ.get("AEGIS_DATA_DIR")
if _DATA_DIR:
    Path(_DATA_DIR).mkdir(parents=True, exist_ok=True)
    _audit = AuditLog(Path(_DATA_DIR) / "audit.db")
    _att_store = AttestationStore(Path(_DATA_DIR) / "attestations.db")
else:
    _audit = AuditLog()
    _att_store = None
_contracts = {
    **_health.contract_registry(),
    **_bfsi.contract_registry(),
}
_mon = ReferenceMonitor(_contracts, _audit, secret=_SIGNING_KEY,
                        signer=_signer, event_bus=_bus,
                        attestation_store=_att_store)


class AegisWebHandler(BaseHTTPRequestHandler):
    timeout = SOCKET_TIMEOUT_S

    def _json(self, code: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # -- identity, auth, rate limit ------------------------------------
    def _presented_key(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("X-API-Key", "").strip()

    def _peer_ip(self) -> str:
        if _TRUST_PROXY:
            # Rightmost entry = appended by our own trusted proxy; the
            # leftmost is client-controlled and spoofable.
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[-1].strip()[:64]
        return self.client_address[0]

    def _guard(self) -> str | None:
        """Authenticate + rate-limit an API call. Returns the server-derived
        client id, or None after sending 401/429. The client id is NEVER
        taken from the request body (a caller must not choose its own
        rate-limit / fatigue bucket)."""
        key = self._presented_key()
        if not _is_authorized(key):
            self._json(401, {"error": "missing or invalid API key"})
            return None
        client = ("key_" + _digest(key).hex()[:12]) if _AUTH_DIGESTS \
            else "ip_" + self._peer_ip()
        lim = _http_limiter.allow(client)
        if not lim.allowed:
            self._json(429, {"error": "rate limit exceeded"})
            return None
        return client

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
            body = json.loads(raw.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return body if isinstance(body, dict) else None

    def do_OPTIONS(self):
        # Same-origin only: no CORS headers are granted.
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        if not path.startswith("/api/"):
            return self._json(404, {"error": "unknown endpoint"})
        client = self._guard()
        if client is None:
            return
        body = self._body()
        if body is None:
            return self._json(400, {"error": "invalid or oversized JSON body"})

        if path == "/api/scan":
            payload = body.get("payload", "")
            if not isinstance(payload, str):
                return self._json(400, {"error": "payload must be a string"})
            source_id = client
            res = _gw.scan(payload, source_id=source_id)

            # Generate sample attestation for the scan
            att = sign_attestation(
                signer=_signer,
                contract_id="aegis.gateway.ingress.v1",
                action="scan_payload",
                decision=res.verdict.name,
                reason=f"score={res.score:.2f} ({res.verdict.name})",
                subject=source_id,
                params={"payload_len": len(payload), "hits": len(res.detector_hits)},
            )

            if _sink is not None:
                _sink.emit("scan", {
                    "verdict": res.verdict.name, "score": res.score,
                    "latency_ms": res.latency_ms, "client": client,
                    "payload_preview": payload[:200],
                    "detector_hits": res.detector_hits,
                    "ts": time.time()})

            return self._json(200, {
                "verdict": res.verdict.name,
                "score": res.score,
                "latency_ms": res.latency_ms,
                "sanitized": res.sanitized,
                "detections": [
                    {"detector": d.detector, "score": d.score,
                     "fired": d.fired, "evidence": d.evidence}
                    for d in res.detections
                ],
                "attestation": {
                    "contract_id": att.contract_id,
                    "action": att.action,
                    "decision": att.decision,
                    "reason": att.reason,
                    "signature": att.signature,
                    "offline_verifiable": True,
                }
            })

        if path == "/api/evaluate":
            action_name = body.get("action", "summarize")
            contract_id = body.get("contract_id", "aegis.health.clinical.v1")
            params = body.get("params", {})
            subject = body.get("subject", client)
            if (not isinstance(action_name, str) or not isinstance(params, dict)
                    or not isinstance(contract_id, str)
                    or not isinstance(subject, str)
                    or len(subject) > MAX_LABEL_LEN):
                return self._json(400, {"error": "invalid action/contract/params/subject"})

            res = _mon.evaluate(Action(action_name, params),
                                Context(contract_id=contract_id,
                                        source_id=client, subject=subject))
            att = res.attestation       # this decision's own proof (no race)
            if _sink is not None:
                _sink.emit("evaluate", {
                    "action": action_name, "contract_id": contract_id,
                    "decision": res.decision.value, "client": client,
                    "ts": time.time()})

            return self._json(200, {
                "decision": res.decision.value,
                "reason": res.reason,
                "allowed": res.allowed,
                "attestation": {
                    "contract_id": att.contract_id if att else contract_id,
                    "action": att.action if att else action_name,
                    "decision": att.decision if att else res.decision.value,
                    "signature": att.signature if att else "",
                    "offline_verifiable": True,
                } if att else None,
            })

        self._json(404, {"error": "unknown endpoint"})

    def do_GET(self):
        clean_path = self.path.split("?")[0]
        if clean_path == "/healthz":
            return self._json(200, {"status": "ok"})
        if clean_path.startswith("/api/") and self._guard() is None:
            return
        if clean_path == "/api/status":
            signer_info: dict[str, Any] = {
                "type": type(_signer).__name__,
            }
            pub = getattr(_signer, "public_key", None)
            if pub is not None:
                signer_info["public_key_hex"] = bytes(pub).hex()
            return self._json(200, {
                "status": "operational",
                "detectors_count": len(_gw.detectors),
                "active_contracts": list(_contracts.keys()),
                "total_events": len(_bus),
                "containment_policy": "FAIL-CLOSED",
                "signer": signer_info,
            })

        # Static file serving from WEB_DIR
        rel_path = clean_path.lstrip("/") or "dashboard.html"
        target_file = (WEB_DIR / rel_path).resolve()

        if not target_file.is_relative_to(WEB_DIR):
            self.send_error(403, "Access denied")
            return

        if not target_file.exists() or target_file.is_dir():
            target_file = WEB_DIR / "index.html"

        content_type, _ = mimetypes.guess_type(str(target_file))
        content_type = content_type or "application/octet-stream"

        try:
            with open(target_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            log.exception("static file error: %s", target_file)
            self.send_error(500, "Internal server error")   # no detail leak

    def log_message(self, fmt, *args):
        # Quiet standard output
        return


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def make_server(host: str = "127.0.0.1", port: int = 8090,
                certfile: str | None = None,
                keyfile: str | None = None) -> ThreadingHTTPServer:
    """Build the threaded server; fail closed on unsafe configuration."""
    if not _AUTH_DIGESTS and not _is_loopback(host) and not _PUBLIC_DEMO:
        raise SystemExit(
            "refusing to bind non-loopback interface without "
            "authentication: set AEGIS_API_KEYS (or AEGIS_PUBLIC_DEMO=1 "
            "for unauthenticated demo deployments)")
    server = ThreadingHTTPServer((host, port), AegisWebHandler)
    server.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def run_server(host: str = "127.0.0.1", port: int = 8090) -> None:
    tls_cert = os.environ.get("AEGIS_TLS_CERT")
    server = make_server(host, port, tls_cert, os.environ.get("AEGIS_TLS_KEY"))
    scheme = "https" if tls_cert else "http"
    mode = "API-key auth ON" if _AUTH_DIGESTS else "open DEV mode (loopback)"
    print("\n" + "=" * 65)
    print("  AEGIS ENTERPRISE COMMAND CENTER // WEB SERVER ACTIVE")
    print(f"  URL: {scheme}://{host}:{port}   [{mode}]")
    print("=" * 65 + "\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer terminated cleanly.")
        server.server_close()


if __name__ == "__main__":
    # Cloud Run sets PORT and K_SERVICE; locally defaults stay loopback:8090.
    _on_gcp = bool(os.environ.get("K_SERVICE"))
    port = int(os.environ.get("PORT") or
               (sys.argv[1] if len(sys.argv) > 1 else 8090))
    host = os.environ.get("AEGIS_HOST") or ("0.0.0.0" if _on_gcp
                                            else "127.0.0.1")
    run_server(host=host, port=port)
