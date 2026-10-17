"""Merkle transparency log over signed attestations.

Regulated deployments need an append-only, independently verifiable record
that a given attestation was included. A Merkle tree gives O(log n)
inclusion proofs: a regulator holds only the root and can verify any
attestation's inclusion without trusting the system's own claims.

Leaves are opaque bytes (callers append e.g. an attestation signature).

This is the RFC 6962 / RFC 9162 Merkle tree: leaves and interior nodes are
hashed under distinct prefixes (0x00 / 0x01) so an interior node can never
be passed off as a leaf, and the tree is split at the largest power of two
strictly below n so its shape is append-stable. That stability is what makes
CONSISTENCY proofs possible: a regulator holding an old root can verify the
log only ever grew (no rewrite or truncation) given any later root.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


_LEAF = b"\x00"
_NODE = b"\x01"


def _hash(b: bytes) -> bytes:
    """Leaf hash (domain-separated)."""
    return hashlib.sha256(_LEAF + b).digest()


def _pair_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(hashes: Sequence[bytes]) -> bytes:
    """Merkle tree hash over already leaf-hashed entries (RFC 6962 2.1)."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = _split(n)
    return _pair_hash(_mth(hashes[:k]), _mth(hashes[k:]))


def _path(m: int, hashes: Sequence[bytes]) -> list[bytes]:
    """Inclusion path PATH(m, D[n]) (RFC 6962 2.1.1)."""
    n = len(hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, hashes[:k]) + [_mth(hashes[k:])]
    return _path(m - k, hashes[k:]) + [_mth(hashes[:k])]


def _subproof(m: int, hashes: Sequence[bytes], complete: bool) -> list[bytes]:
    """SUBPROOF(m, D[n], b) (RFC 6962 2.1.2)."""
    n = len(hashes)
    if m == n:
        return [] if complete else [_mth(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, hashes[:k], complete) + [_mth(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [_mth(hashes[:k])]


@dataclass(frozen=True)
class InclusionProof:
    index: int
    leaf: bytes                       # hashed leaf (bottom-level node)
    path: tuple[bytes, ...]           # sibling hashes, leaf -> root
    size: int = 0                     # tree size the proof was cut against

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "leaf": self.leaf.hex(),
            "path": [p.hex() for p in self.path],
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "InclusionProof":
        return cls(
            index=int(d["index"]),
            leaf=bytes.fromhex(d["leaf"]),
            path=tuple(bytes.fromhex(p) for p in d["path"]),
            size=int(d.get("size", 0)))


class MerkleLog:
    """Append-only Merkle tree with inclusion proofs."""

    def __init__(self, leaves: Sequence[bytes] = ()) -> None:
        self._leaves: list[bytes] = [bytes(leaf) for leaf in leaves]

    def append(self, leaf: bytes) -> int:
        """Append a raw leaf; returns its index."""
        self._leaves.append(bytes(leaf))
        return len(self._leaves) - 1

    @property
    def leaves(self) -> tuple[bytes, ...]:
        return tuple(self._leaves)

    def __len__(self) -> int:
        return len(self._leaves)

    def _hashes(self, size: int | None = None) -> list[bytes]:
        leaves = self._leaves if size is None else self._leaves[:size]
        return [_hash(leaf) for leaf in leaves]

    def root(self) -> bytes:
        return _mth(self._hashes())

    def root_at(self, size: int) -> bytes:
        """Root of the log as it was when it held `size` leaves."""
        if not 0 <= size <= len(self._leaves):
            raise IndexError(f"size {size} out of range")
        return _mth(self._hashes(size))

    def proof(self, index: int) -> InclusionProof:
        """Inclusion proof for the leaf at `index`."""
        if not 0 <= index < len(self._leaves):
            raise IndexError(f"leaf index {index} out of range")
        hashes = self._hashes()
        return InclusionProof(index=index, leaf=hashes[index],
                              path=tuple(_path(index, hashes)),
                              size=len(hashes))

    @staticmethod
    def verify(proof: InclusionProof, root: bytes) -> bool:
        """Recompute the root from an inclusion proof (RFC 9162 2.1.3.2)."""
        if not 0 <= proof.index < proof.size:
            return False
        fn, sn = proof.index, proof.size - 1
        r = proof.leaf
        for p in proof.path:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _pair_hash(p, r)
                if not fn & 1:
                    while not fn & 1 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                r = _pair_hash(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and hmac.compare_digest(r, root)

    # -- consistency (append-only) proofs ---------------------------------
    def consistency_proof(self, first_size: int,
                          second_size: int | None = None
                          ) -> tuple[bytes, ...]:
        """Proof that the log of `first_size` leaves is a prefix of the log
        of `second_size` leaves (default: current size)."""
        second = len(self._leaves) if second_size is None else second_size
        if not 0 <= first_size <= second <= len(self._leaves):
            raise IndexError("invalid consistency proof sizes")
        if first_size in (0, second):
            return ()
        return tuple(_subproof(first_size, self._hashes(second), True))

    @staticmethod
    def verify_consistency(first_size: int, first_root: bytes,
                           second_size: int, second_root: bytes,
                           proof: Sequence[bytes]) -> bool:
        """Verify the log only grew between two signed roots
        (RFC 9162 2.1.4.2)."""
        if first_size < 0 or first_size > second_size:
            return False
        if first_size == second_size:
            return not proof and hmac.compare_digest(first_root, second_root)
        if first_size == 0:
            return not proof
        path = list(proof)
        if first_size & (first_size - 1) == 0:      # exact power of two
            path.insert(0, first_root)
        if not path:
            return False
        fn, sn = first_size - 1, second_size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = path[0]
        for c in path[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr = _pair_hash(c, fr)
                sr = _pair_hash(c, sr)
                if not fn & 1:
                    while not fn & 1 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                sr = _pair_hash(sr, c)
            fn >>= 1
            sn >>= 1
        return (sn == 0 and hmac.compare_digest(fr, first_root)
                and hmac.compare_digest(sr, second_root))


__all__ = ["InclusionProof", "MerkleLog"]
