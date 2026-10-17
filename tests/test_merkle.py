"""Merkle transparency log tests. Run: python -m unittest tests.test_merkle -v"""
from __future__ import annotations

import hashlib
import unittest

from aegis.core import InclusionProof, MerkleLog


class MerkleLogTests(unittest.TestCase):
    def test_empty_root_is_stable(self):
        self.assertEqual(MerkleLog().root(), MerkleLog().root())
        self.assertEqual(len(MerkleLog().root()), 32)

    def test_single_leaf_proof_verifies(self):
        log = MerkleLog()
        log.append(b"a")
        self.assertTrue(log.verify(log.proof(0), log.root()))

    def test_all_leaves_verify(self):
        log = MerkleLog([b"a", b"b", b"c", b"d", b"e"])
        root = log.root()
        for i in range(len(log)):
            self.assertTrue(log.verify(log.proof(i), root))

    def test_tampered_leaf_fails(self):
        log = MerkleLog([b"a", b"b", b"c"])
        root = log.root()
        proof = log.proof(1)
        bad = InclusionProof(index=1,
                             leaf=hashlib.sha256(b"x").digest(),
                             path=proof.path)
        self.assertFalse(log.verify(bad, root))

    def test_wrong_root_fails(self):
        log = MerkleLog([b"a", b"b"])
        proof = log.proof(0)
        self.assertFalse(log.verify(proof, hashlib.sha256(b"other").digest()))

    def test_out_of_range_raises(self):
        log = MerkleLog([b"a"])
        with self.assertRaises(IndexError):
            log.proof(5)

    def test_proof_dict_roundtrip(self):
        log = MerkleLog([b"a", b"b", b"c"])
        proof = log.proof(2)
        restored = InclusionProof.from_dict(proof.to_dict())
        self.assertTrue(log.verify(restored, log.root()))


if __name__ == "__main__":
    unittest.main()
