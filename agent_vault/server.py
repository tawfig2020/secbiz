"""Agent Vault HTTP server (stdlib only) — Cloud Run entrypoint.

Endpoints:
    POST /process          full containment pipeline on untrusted text
    POST /evaluate_action  mediate one action against the contract
    POST /inspect_response egress scan of a model/tool output
    GET  /attestations     append-only signed decision log
    GET  /healthz          liveness probe
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from agent_vault import AgentVault

_vault = AgentVault()


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, body: Any) -> None:
        data = json.dumps(body, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            out = json.loads(raw.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return out if isinstance(out, dict) else {}

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self._json(200, {"status": "ok", "service": "agent-vault"})
        if self.path == "/attestations":
            return self._json(200, {"attestations": _vault.attestations()})
        if self.path == "/":
            return self._json(200, {
                "service": "Aegis Agent Vault",
                "contract_id": _vault.contract.contract_id,
                "classifier": _vault.classifier_name,
                "thesis": "a compromised banking agent cannot cause "
                          "irreversible harm — and it proves it",
                "endpoints": ["/process", "/evaluate_action",
                              "/inspect_response", "/attestations",
                              "/healthz"],
            })
        self._json(404, {"error": "unknown endpoint"})

    def do_POST(self) -> None:
        body = self._body()
        if self.path == "/process":
            text = body.get("text", "")
            if not isinstance(text, str):
                return self._json(400, {"error": "text must be a string"})
            return self._json(200, _vault.process(
                text, body.get("source_id", "customer")).to_dict())
        if self.path == "/evaluate_action":
            action = body.get("action", "")
            params = body.get("params") or {}
            if not isinstance(action, str) or not isinstance(params, dict):
                return self._json(400, {"error": "invalid action/params"})
            return self._json(200, _vault.evaluate_action(
                action, params, body.get("subject", "customer"),
                body.get("source_id", "api")))
        if self.path == "/inspect_response":
            output = body.get("output", "")
            if not isinstance(output, str):
                return self._json(400, {"error": "output must be a string"})
            return self._json(200, _vault.inspect_response(output))
        self._json(404, {"error": "unknown endpoint"})

    def log_message(self, fmt, *args):  # quiet stdlib logging
        return


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    host = "0.0.0.0"
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    print(f"Aegis Agent Vault listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
