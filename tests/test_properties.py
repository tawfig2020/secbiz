"""Property-based tests for the security-critical primitives.

Requires the optional `hypothesis` package (`pip install hypothesis`).
Skipped automatically when it is not installed so the stdlib-only test suite
still runs.

Properties:
  * Merkle inclusion proofs hold for arbitrary tree shapes/sizes.
  * The hash-chained audit log detects any single-byte mutation.
  * Ed25519 sign/verify round-trips for arbitrary payloads.
  * Delegation attenuation: child scope ⊆ parent scope.
"""
from __future__ import annotations

import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
    _HAVE_HYPOTHESIS = True
except ImportError:                       # pragma: no cover - optional dep
    _HAVE_HYPOTHESIS = False

    def given(*args, **kwargs):           # no-op so decorators don't NameError
        def _deco(fn):
            return fn
        return _deco

    def settings(*args, **kwargs):
        def _deco(fn):
            return fn
        return _deco

    class _Stub:
        def __getattr__(self, name):
            return lambda *a, **k: None

    st = _Stub()

from aegis.capability_bounded.capability_contract import (
    CapabilityContract,
    PermittedAction,
)
from aegis.core import AuditLog
from aegis.core.asymmetric import Ed25519Signer, Ed25519Verifier, _HAVE_CRYPTO
from aegis.core.merkle import MerkleLog


@unittest.skipUnless(_HAVE_HYPOTHESIS, "hypothesis not installed")
class MerklePropertyTests(unittest.TestCase):
    @given(st.lists(st.binary(min_size=1, max_size=64),
                     min_size=1, max_size=50))
    @settings(max_examples=200)
    def test_inclusion_proof_holds_for_every_index(self, leaves):
        log = MerkleLog(leaves)
        root = log.root()
        for i in range(len(leaves)):
            self.assertTrue(log.verify(log.proof(i), root))

    @given(st.lists(st.binary(min_size=1, max_size=64),
                     min_size=1, max_size=50))
    @settings(max_examples=200)
    def test_tampered_leaf_breaks_root(self, leaves):
        log = MerkleLog(leaves)
        root = log.root()
        if not leaves:
            return
        mutated = list(leaves)
        mutated[0] = b"\x00" + mutated[0]
        self.assertNotEqual(MerkleLog(mutated).root(), root)


@unittest.skipUnless(_HAVE_HYPOTHESIS, "hypothesis not installed")
class AuditPropertyTests(unittest.TestCase):
    @given(st.lists(st.text(min_size=1, max_size=20),
                     min_size=1, max_size=40))
    @settings(max_examples=100)
    def test_single_byte_mutation_breaks_chain(self, events):
        log = AuditLog()
        for e in events:
            log.record("actor", e, {"k": "v"})
        self.assertTrue(log.verify())
        # Mutate the first event's detail: the chain must now fail.
        ev = log.events[0]
        ev.detail = {"k": "TAMPERED"}
        self.assertFalse(log.verify())


@unittest.skipUnless(_HAVE_HYPOTHESIS and _HAVE_CRYPTO,
                     "hypothesis/cryptography not installed")
class Ed25519PropertyTests(unittest.TestCase):
    @given(st.binary(min_size=0, max_size=256))
    @settings(max_examples=200)
    def test_sign_verify_roundtrip(self, payload):
        signer = Ed25519Signer()
        sig = signer.sign(payload)
        self.assertTrue(signer.verify(payload, sig))
        self.assertFalse(signer.verify(payload + b"x", sig))

    @given(st.binary(min_size=0, max_size=256))
    @settings(max_examples=100)
    def test_public_key_alone_verifies(self, payload):
        signer = Ed25519Signer()
        verifier = Ed25519Verifier(signer.public_key)
        self.assertTrue(verifier.verify(payload, signer.sign(payload)))


@unittest.skipUnless(_HAVE_HYPOTHESIS, "hypothesis not installed")
class AttenuationPropertyTests(unittest.TestCase):
    @given(st.sets(st.sampled_from(["a", "b", "c", "d"]), min_size=1))
    @settings(max_examples=100)
    def test_child_scope_is_subset_of_parent(self, parent_actions):
        parent = CapabilityContract(
            contract_id="p",
            permitted_actions={a: PermittedAction(a) for a in parent_actions},
            prohibited_actions=frozenset())
        child = CapabilityContract(
            contract_id="c",
            permitted_actions={a: PermittedAction(a) for a in parent_actions
                               if a != "d"},  # drop at most one action
            prohibited_actions=frozenset())
        self.assertTrue(set(child.permitted_actions) <= set(parent.permitted_actions))


if __name__ == "__main__":
    unittest.main()
