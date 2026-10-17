"""Regression tests for the second-pass review fixes."""
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace

from aegis.capability_bounded import (
    Action,
    ApprovalQueue,
    CapabilityContract,
    Context,
    ExecutorAgent,
    PermittedAction,
    ReferenceMonitor,
    delegate_contract,
)
from aegis.core import (
    AttestationStore,
    AuditLog,
    Ed25519Signer,
    Ed25519Verifier,
    MerkleLog,
    verify_attestation,
)
from aegis.core.asymmetric import _HAVE_CRYPTO


def _contract(cid="c.v1", **kw):
    base = dict(
        contract_id=cid,
        permitted_actions={"pay": PermittedAction(
            "pay", {"max_amount": 100, "requires_human_approval": True})},
        prohibited_actions=frozenset(), deny_unlisted=True)
    base.update(kw)
    return CapabilityContract(**base)


class DelegationEscapes(unittest.TestCase):
    def test_child_cannot_drop_human_approval(self):
        parent = _contract()
        child_req = _contract("child", permitted_actions={
            "pay": PermittedAction("pay", {"requires_human_approval": False})})
        child = delegate_contract(parent, child_req)
        self.assertTrue(
            child.permitted_actions["pay"].constraints[
                "requires_human_approval"])

    def test_child_cannot_disable_deny_unlisted(self):
        child = delegate_contract(
            _contract(), _contract("child", deny_unlisted=False))
        self.assertTrue(child.deny_unlisted)


class ExecutorAtMostOnce(unittest.TestCase):
    def test_concurrent_redeem_executes_once(self):
        c = _contract(permitted_actions={"go": PermittedAction("go", {})})
        audit = AuditLog()
        mon = ReferenceMonitor({c.contract_id: c}, audit, secret=b"k" * 32)
        ex = ExecutorAgent(mon, audit)
        calls = []
        ex.register_tool("go", lambda: calls.append(1))
        tok = mon.evaluate(Action("go"), Context(c.contract_id)).token
        threads = [threading.Thread(target=ex.execute, args=(tok,))
                   for _ in range(16)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(calls), 1)

    def test_failed_tool_burns_token(self):
        c = _contract(permitted_actions={"go": PermittedAction("go", {})})
        audit = AuditLog()
        mon = ReferenceMonitor({c.contract_id: c}, audit, secret=b"k" * 32)
        ex = ExecutorAgent(mon, audit)

        def boom():
            raise RuntimeError("x")
        ex.register_tool("go", boom)
        tok = mon.evaluate(Action("go"), Context(c.contract_id)).token
        self.assertFalse(ex.execute(tok).executed)
        self.assertFalse(mon.verify(tok))


class ApprovalSeparationOfDuties(unittest.TestCase):
    def test_requester_cannot_self_approve_and_no_double_resolve(self):
        q = ApprovalQueue()
        aid = q.enqueue(Action("pay"), Context("c", subject="alice"), "r")
        with self.assertRaises(PermissionError):
            q.approve(aid, "alice")
        q.approve(aid, "bob")
        with self.assertRaises(ValueError):
            q.deny(aid, "carol")


class MerkleConsistency(unittest.TestCase):
    def test_all_prefix_pairs_verify(self):
        log = MerkleLog([bytes([i]) for i in range(20)])
        for m in range(0, 21):
            for n in range(m, 21):
                proof = log.consistency_proof(m, n)
                self.assertTrue(MerkleLog.verify_consistency(
                    m, log.root_at(m), n, log.root_at(n), proof), (m, n))

    def test_inclusion_all_sizes(self):
        for n in range(1, 18):
            log = MerkleLog([bytes([i]) for i in range(n)])
            for i in range(n):
                self.assertTrue(log.verify(log.proof(i), log.root()))

    def test_rewrite_detected(self):
        a = MerkleLog([b"1", b"2", b"3", b"4", b"5"])
        forged = MerkleLog([b"1", b"X", b"3", b"4", b"5", b"6"])
        proof = forged.consistency_proof(5)
        self.assertFalse(MerkleLog.verify_consistency(
            5, a.root(), 6, forged.root(), proof))


class Durability(unittest.TestCase):
    def test_audit_persists_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "a.db")
            log = AuditLog(p)
            log.record("a", "e1", {"k": 1})
            log.record("a", "e2", {"k": (1, 2)})
            log.close()
            again = AuditLog(p)
            self.assertEqual(len(again.events), 2)
            again.record("a", "e3")
            self.assertTrue(again.verify())
            again.close()
            db = sqlite3.connect(p)
            db.execute("UPDATE audit SET event='forged' WHERE seq=0")
            db.commit()
            db.close()
            with self.assertRaises(ValueError):
                AuditLog(p)

    def test_attestations_survive_restart(self):
        c = _contract(permitted_actions={"go": PermittedAction("go", {})})
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "att.db")
            key = b"k" * 32
            store = AttestationStore(p)
            mon = ReferenceMonitor({c.contract_id: c}, AuditLog(),
                                   secret=key, attestation_store=store)
            mon.evaluate(Action("go"), Context(c.contract_id))
            store.close()
            store2 = AttestationStore(p)
            try:
                mon2 = ReferenceMonitor({c.contract_id: c}, AuditLog(),
                                        secret=key, attestation_store=store2)
                log = mon2.attestation_log
                self.assertEqual(len(log), 1)
                self.assertTrue(verify_attestation(key, log[0]))
            finally:
                store2.close()


@unittest.skipUnless(_HAVE_CRYPTO, "optional 'cryptography' not installed")
class Asymmetric(unittest.TestCase):
    def test_verifier_cannot_sign_and_rejects_forgery(self):
        signer = Ed25519Signer()
        sig = signer.sign(b"msg")
        ver = Ed25519Verifier(signer.public_key)
        self.assertTrue(ver.verify(b"msg", sig))
        self.assertFalse(ver.verify(b"other", sig))
        self.assertFalse(ver.verify(b"msg", "zz"))
        with self.assertRaises(PermissionError):
            ver.sign(b"msg")


if __name__ == "__main__":
    unittest.main()
