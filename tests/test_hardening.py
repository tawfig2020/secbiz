"""Regression tests for the code-audit fixes. Run: python -m unittest tests.test_hardening -v"""
from __future__ import annotations

import threading
import unittest
from dataclasses import replace

from aegis.capability_bounded import Action, Context, ReferenceMonitor
from aegis.capability_bounded.capability_contract import CapabilityContract
from aegis.config import Settings
from aegis.core import AuditLog
from aegis.core.asymmetric import (
    Ed25519Signer,
    Ed25519Verifier,
    _HAVE_CRYPTO,
    default_signer,
)
from aegis.core.attestation import sign_attestation, verify_attestation
from aegis.core.merkle import InclusionProof, MerkleLog
from aegis.plugins.feeds import UrlFeed
from aegis.semantic_gateway import SemanticGateway, Verdict

KEY = b"k" * 32


class MerkleHardeningTests(unittest.TestCase):
    def test_odd_duplication_does_not_collide(self):
        # [a,b,c] and [a,b,c,c] used to share a root.
        self.assertNotEqual(MerkleLog([b"a", b"b", b"c"]).root(),
                            MerkleLog([b"a", b"b", b"c", b"c"]).root())

    def test_interior_node_is_not_a_valid_leaf(self):
        log = MerkleLog([b"a", b"b"])
        proof = log.proof(0)
        forged = InclusionProof(index=0, leaf=proof.leaf, path=(),
                                size=1)
        self.assertFalse(log.verify(forged, log.root()))

    def test_proof_with_wrong_size_fails(self):
        log = MerkleLog([b"a", b"b", b"c"])
        p = log.proof(1)
        for bad in (2, 8, 100):
            self.assertFalse(log.verify(replace(p, size=bad), log.root()))

    def test_index_outside_size_rejected(self):
        log = MerkleLog([b"a", b"b"])
        p = log.proof(0)
        self.assertFalse(log.verify(replace(p, index=5), log.root()))


class AttestationCanonicalTests(unittest.TestCase):
    def test_delimiter_injection_changes_signature(self):
        base = dict(contract_id="c", action="a", decision="DENY",
                    params={}, now=1.0)
        a = sign_attestation(KEY, reason="x|y", subject="z", **base)
        # Same concatenation under the old '|' scheme, different fields.
        forged = replace(a, reason="x", subject="y|z")
        self.assertTrue(verify_attestation(KEY, a))
        self.assertFalse(verify_attestation(KEY, forged))


class MonitorTests(unittest.TestCase):
    def _mon(self, **contract_kw):
        c = CapabilityContract(
            contract_id="t.v1", permitted_actions={}, **contract_kw)
        return ReferenceMonitor({c.contract_id: c}, AuditLog(), secret=KEY)

    def test_unlisted_allowed_contract_does_not_crash(self):
        mon = self._mon(deny_unlisted=False)
        res = mon.evaluate(Action("anything"), Context("t.v1"))
        self.assertTrue(res.allowed)

    def test_expired_nonces_are_pruned(self):
        c = CapabilityContract.from_dict({
            "contract_id": "t.v1",
            "permitted_actions": [{"action": "read", "constraints": {}}]})
        mon = ReferenceMonitor({"t.v1": c}, AuditLog(), secret=KEY,
                               token_ttl=-1.0)
        for _ in range(5):
            mon.evaluate(Action("read"), Context("t.v1"))
        self.assertLessEqual(len(mon._issued_nonce), 1)

    def test_token_roundtrip_and_tamper(self):
        c = CapabilityContract.from_dict({
            "contract_id": "t.v1",
            "permitted_actions": [{"action": "read", "constraints": {}}]})
        mon = ReferenceMonitor({"t.v1": c}, AuditLog(), secret=KEY)
        tok = mon.evaluate(Action("read"), Context("t.v1")).token
        self.assertTrue(mon.verify(tok))
        self.assertFalse(mon.verify(replace(tok, action="write")))
        mon.consume(tok)
        self.assertFalse(mon.verify(tok))


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography package not installed")
class AsymmetricDefaultTests(unittest.TestCase):
    def test_default_signer_prefers_ed25519(self):
        self.assertIsInstance(default_signer(), Ed25519Signer)

    def test_monitor_defaults_to_ed25519_when_no_secret(self):
        c = CapabilityContract.from_dict({
            "contract_id": "t.v1",
            "permitted_actions": [{"action": "read", "constraints": {}}]})
        mon = ReferenceMonitor({"t.v1": c}, AuditLog())
        self.assertIsInstance(mon._signer, Ed25519Signer)
        res = mon.evaluate(Action("read"), Context("t.v1"))
        self.assertIsNotNone(res.attestation)
        # The public key alone must verify the proof (no signing capability).
        verifier = Ed25519Verifier(mon._signer.public_key)
        self.assertTrue(verify_attestation(None, res.attestation,
                                           signer=verifier))

    def test_ed25519_verifier_cannot_sign(self):
        signer = Ed25519Signer()
        verifier = Ed25519Verifier(signer.public_key)
        with self.assertRaises(PermissionError):
            verifier.sign(b"payload")

    def test_ed25519_roundtrip_and_tamper(self):
        signer = Ed25519Signer()
        sig = signer.sign(b"payload")
        self.assertTrue(signer.verify(b"payload", sig))
        self.assertFalse(signer.verify(b"tampered", sig))


class AuditConcurrencyTests(unittest.TestCase):
    def test_concurrent_records_keep_chain_valid(self):
        log = AuditLog()

        def work():
            for _ in range(200):
                log.record("t", "e", {})

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(log.events), 1600)
        self.assertTrue(log.verify())


class GatewayFailClosedTests(unittest.TestCase):
    def test_detector_exception_blocks(self):
        class Boom:
            name = "boom"

            def scan(self, text, ctx):
                raise RuntimeError("x")

        gw = SemanticGateway(detectors=[Boom()])
        res = gw.scan("hello")
        self.assertIs(res.verdict, Verdict.BLOCK)


class FeedAndConfigTests(unittest.TestCase):
    def test_non_http_feed_scheme_rejected(self):
        feed = UrlFeed({"x": "file:///etc/passwd"})
        with self.assertRaises(ValueError):
            feed.fetch("x")

    def test_secrets_not_in_repr(self):
        s = Settings(stripe_api_key="sk_live_SECRET",
                     feed_cisa_api_key="CISA_SECRET",
                     database_url="postgres://u:pw@h/db")
        text = repr(s)
        for secret in ("sk_live_SECRET", "CISA_SECRET", "pw@h"):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
