"""Self-serve Solo tier tests. Run: python -m unittest tests.test_selfserve -v"""
from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection

from aegis.plugins import (
    SOLO,
    InMemoryBilling,
    PluginManifest,
    PluginRegistry,
    StarterService,
    UsageMeter,
    serve_http,
)


class MeteringTests(unittest.TestCase):
    def test_meter_accumulates_usage(self):
        billing = InMemoryBilling()
        meter = UsageMeter(billing=billing)
        meter.record_scan("t1", 100, blocked=True)
        meter.record_scan("t1", 50, blocked=False)
        meter.record_action("t1", blocked=False)

        snap = meter.snapshot("t1")
        self.assertEqual(snap["scans"], 2)
        self.assertEqual(snap["actions"], 1)
        self.assertEqual(snap["blocked"], 1)
        self.assertEqual(snap["bytes_scanned"], 150)
        self.assertEqual(len(billing.records), 3)

    def test_meter_without_billing_does_not_raise(self):
        meter = UsageMeter()
        meter.record_scan("t1", 10, blocked=False)
        self.assertEqual(meter.snapshot("t1")["scans"], 1)


class StarterServiceTests(unittest.TestCase):
    def setUp(self):
        plugin = PluginRegistry().resolve(PluginManifest(tier=SOLO))
        self.billing = InMemoryBilling()
        self.service = StarterService(plugin, UsageMeter(billing=self.billing))

    def test_issue_and_authenticate(self):
        key = self.service.issue_key(email="a@b.c")["api_key"]
        self.assertTrue(self.service.authenticate(key))
        self.assertFalse(self.service.authenticate("nope"))

    def test_scan_meters_usage(self):
        key = self.service.issue_key(email="a@b.c")["api_key"]
        verdict = self.service.scan(key, "hello world")
        self.assertEqual(verdict.verdict, "ALLOW")
        snap = self.service.usage(key)
        self.assertEqual(snap["scans"], 1)
        self.assertEqual(len(self.billing.records), 1)

    def test_evaluate_action_meters_and_enforces(self):
        key = self.service.issue_key(email="a@b.c")["api_key"]
        verdict = self.service.evaluate_action(
            key, "execute_payment", "aegis.generic.assistant.v1")
        self.assertEqual(verdict.verdict, "DENY")
        snap = self.service.usage(key)
        self.assertEqual(snap["actions"], 1)
        self.assertEqual(snap["blocked"], 1)


class HttpApiTests(unittest.TestCase):
    def _start(self):
        plugin = PluginRegistry().resolve(PluginManifest(tier=SOLO))
        service = StarterService(plugin)
        server = serve_http(service, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port, thread

    def _post(self, port, path, body):
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", path, body=json.dumps(body),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        return resp.status, data

    def test_signup_scan_usage_roundtrip(self):
        server, port, thread = self._start()
        try:
            status, data = self._post(port, "/signup", {"email": "x@y.z"})
            self.assertEqual(status, 201)
            key = data["api_key"]

            status, data = self._post(port, "/scan",
                                      {"api_key": key, "payload": "hello"})
            self.assertEqual(status, 200)
            self.assertEqual(data["verdict"], "ALLOW")

            status, data = self._post(
                port, "/evaluate_action",
                {"api_key": key, "action": "execute_payment",
                 "contract_id": "aegis.generic.assistant.v1"})
            self.assertEqual(status, 200)
            self.assertEqual(data["verdict"], "DENY")

            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", f"/usage?api_key={key}")
            resp = conn.getresponse()
            usage = json.loads(resp.read())
            conn.close()
            self.assertEqual(usage["scans"], 1)
            self.assertEqual(usage["actions"], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_invalid_key_fails_closed(self):
        server, port, thread = self._start()
        try:
            status, data = self._post(port, "/scan",
                                      {"api_key": "bad", "payload": "hello"})
            self.assertEqual(status, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
