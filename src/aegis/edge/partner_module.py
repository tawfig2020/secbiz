"""Partner edge module: Aegis as a plug-in on programmable data planes.

Differentiation (Part 4): Google Cloud's Agent Gateway lets partners inject
custom logic into the request path; Aegis's answer is the only partner
module that returns *provable containment* — every verdict carries a
signed attestation, and action decisions defer to capability contracts
enforced outside the model.

Two integration surfaces:

  inspect_request(payload)  -> verdict + score + detector hits   (inbound)
  inspect_response(output)  -> verdict + sanitized output        (egress)
  evaluate_action(...)      -> contract decision + attestation   (actions)

serve_http() exposes the same surface over a dependency-free stdlib HTTP
endpoint so a data-plane can call it without importing Python code.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Mapping

from ..capability_bounded.reference_monitor import (
    Action,
    Context,
    ReferenceMonitor,
)
from ..semantic_gateway.gateway import SemanticGateway


@dataclass(frozen=True)
class ModuleVerdict:
    """What a data-plane plugin returns for each inspected unit."""
    allow: bool
    verdict: str                    # ALLOW / SANITIZE / BLOCK
    score: float
    latency_ms: float
    detector_hits: dict[str, float] = field(default_factory=dict)
    sanitized: str = ""
    reason: str = ""
    attestation: str = ""           # signature prefix proving the decision

    def to_dict(self) -> dict[str, Any]:
        return {"allow": self.allow, "verdict": self.verdict,
                "score": self.score, "latency_ms": self.latency_ms,
                "detector_hits": self.detector_hits,
                "sanitized": self.sanitized, "reason": self.reason,
                "attestation": self.attestation}


class AegisModule:
    """Data-plane plugin: gateway scan + contract enforce + egress scan."""

    def __init__(self, gateway: SemanticGateway,
                 monitor: ReferenceMonitor | None = None) -> None:
        self.gateway = gateway
        self.monitor = monitor

    # -- inbound ----------------------------------------------------------
    def inspect_request(self, payload: str,
                        source_id: str = "edge") -> ModuleVerdict:
        r = self.gateway.scan(payload, source_id=source_id)
        return ModuleVerdict(
            allow=r.verdict.name == "ALLOW",
            verdict=r.verdict.name, score=r.score,
            latency_ms=r.latency_ms, detector_hits=r.detector_hits,
            sanitized=r.sanitized)

    # -- egress -----------------------------------------------------------
    def inspect_response(self, output: str) -> ModuleVerdict:
        r = self.gateway.scan_output(output)
        return ModuleVerdict(
            allow=r.verdict.name == "ALLOW",
            verdict=r.verdict.name, score=r.score,
            latency_ms=r.latency_ms, detector_hits=r.detector_hits,
            sanitized=r.sanitized)

    # -- actions ----------------------------------------------------------
    def evaluate_action(self, action: str, contract_id: str,
                        params: Mapping[str, Any] | None = None,
                        source_id: str = "edge") -> ModuleVerdict:
        if self.monitor is None:
            return ModuleVerdict(allow=False, verdict="BLOCK", score=1.0,
                                 latency_ms=0.0,
                                 reason="no ReferenceMonitor attached")
        res = self.monitor.evaluate(
            Action(action, params or {}),
            Context(contract_id=contract_id, source_id=source_id))
        att = self.monitor.attestation_log[-1].signature[:16] \
            if self.monitor.attestation_log else ""
        return ModuleVerdict(
            allow=res.allowed, verdict=res.decision.value,
            score=0.0 if res.allowed else 1.0, latency_ms=0.0,
            reason=res.reason, attestation=att)


# ------------------------------------------------------------- HTTP adapter
def make_handler(module: AegisModule):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, code: int, body: Mapping[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                return {}

        def do_POST(self):                      # noqa: N802 (stdlib API)
            body = self._body()
            if self.path == "/inspect_request":
                v = module.inspect_request(
                    body.get("payload", ""), body.get("source_id", "edge"))
                return self._json(200, v.to_dict())
            if self.path == "/inspect_response":
                v = module.inspect_response(body.get("output", ""))
                return self._json(200, v.to_dict())
            if self.path == "/evaluate_action":
                v = module.evaluate_action(
                    body.get("action", ""), body.get("contract_id", ""),
                    body.get("params"), body.get("source_id", "edge"))
                return self._json(200, v.to_dict())
            self._json(404, {"error": "unknown endpoint"})

        def do_GET(self):                       # noqa: N802
            if self.path == "/healthz":
                return self._json(200, {"status": "ok"})
            self._json(404, {"error": "unknown endpoint"})

        def log_message(self, fmt, *args):      # quiet stdlib logging
            return

    return Handler


def serve_http(module: AegisModule, host: str = "127.0.0.1",
               port: int = 8088) -> HTTPServer:
    """Start a stdlib HTTP server exposing the module. Caller manages it."""
    return HTTPServer((host, port), make_handler(module))
