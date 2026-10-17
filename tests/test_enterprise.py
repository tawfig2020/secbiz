"""Enterprise/Regulated tier tests. Run: python -m unittest tests.test_enterprise -v"""
from __future__ import annotations

import unittest

from aegis.core import verify_attestation
from aegis.plugins import (
    ENTERPRISE,
    CloudKmsClient,
    EnterpriseService,
    FakeKmsClient,
    KmsSigner,
    PluginRegistry,
    StaticFeed,
)
from aegis.semantic_gateway.classifier import GeminiClassifier


class FakeGeminiClient:
    def score(self, text, detections):
        return 0.0


class EnterpriseServiceTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry()
        self.kms = FakeKmsClient()
        self.feeds = StaticFeed({
            "FS-ISAC": ["sig-a", "sig-b"],
            "H-ISAC": ["sig-c"],
        })

    def _onboard(self):
        return EnterpriseService.onboard(
            self.registry, verticals=("bfsi",),
            kms_client=self.kms, feed_source=self.feeds,
            gemini_client=FakeGeminiClient())

    def test_onboard_resolves_enterprise(self):
        service = self._onboard()
        self.assertEqual(service.plugin.tier, ENTERPRISE)

    def test_kms_signer_is_wired(self):
        service = self._onboard()
        self.assertIsInstance(service.plugin.monitor._signer, KmsSigner)

    def test_semantic_classifier_is_wired(self):
        service = self._onboard()
        self.assertIsInstance(service.plugin.gateway.classifier, GeminiClassifier)

    def test_attestations_are_kms_signed(self):
        service = self._onboard()
        service.evaluate_action(
            "execute_payment", "aegis.generic.assistant.v1")
        att = service.plugin.monitor.attestation_log[-1]
        self.assertTrue(verify_attestation(None, att, signer=KmsSigner(self.kms)))

    def test_merkle_inclusion_proof(self):
        service = self._onboard()
        service.evaluate_action(
            "execute_payment", "aegis.generic.assistant.v1")
        service.evaluate_action(
            "read_document", "aegis.generic.assistant.v1")

        self.assertEqual(service.attestation_count(), 2)
        root = service.attestation_root()
        self.assertEqual(len(bytes.fromhex(root)), 32)
        for i in range(service.attestation_count()):
            proof = service.inclusion_proof(i)
            self.assertTrue(service.verify_proof(proof, root))

    def test_poll_feeds_ingests_signatures(self):
        service = self._onboard()
        counts = service.poll_feeds(("FS-ISAC", "H-ISAC"))
        self.assertEqual(counts, {"FS-ISAC": 2, "H-ISAC": 1})

    def test_kms_signer_refuses_without_client(self):
        signer = KmsSigner()
        with self.assertRaises(RuntimeError):
            signer.sign(b"payload")

    def test_cloud_kms_client_adapter(self):
        import hashlib
        import hmac

        key = b"k" * 32

        def sign(payload):
            return hmac.new(key, payload, hashlib.sha256).digest()

        def verify(payload, signature):
            expected = hmac.new(key, payload, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)

        client = CloudKmsClient(sign, verify)
        sig = client.sign(b"payload")
        self.assertTrue(client.verify(b"payload", sig))
        self.assertFalse(client.verify(b"payload", b"bad"))


if __name__ == "__main__":
    unittest.main()
