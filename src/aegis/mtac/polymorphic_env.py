"""Polymorphic environment (Pillar 4): moving-target surface rotation.

Internal resource names (services, schemas, API paths) are deterministically
remapped every epoch under a per-epoch key from the KeyManager. Key-holding
microservices resolve current names; anything an intruder memorized last
epoch is dead noise. In production this maps to Istio route reassignment +
schema aliasing; here it models the rotation semantics and the stolen-map
failure mode.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from aegis.mtac.key_manager import KeyManager, LocalKeyManager


@dataclass(frozen=True)
class EpochMap:
    epoch: int
    mapping: dict[str, str]             # logical name -> ephemeral name
    valid_until: float


class PolymorphicEnvironment:
    def __init__(self, key_manager: KeyManager | None = None,
                 epoch_seconds: float = 5.0,
                 alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> None:
        self._km = key_manager or LocalKeyManager()
        self.epoch_seconds = epoch_seconds
        self._alphabet = alphabet

    def _epoch_at(self, t: float) -> int:
        return int(t // self.epoch_seconds)

    def _ephemeral(self, logical: str, epoch: int, length: int = 16) -> str:
        digest = hmac.new(self._km.epoch_key(epoch), logical.encode(),
                        hashlib.sha256).digest()
        return "".join(self._alphabet[b % len(self._alphabet)]
                       for b in digest[:length])

    def map_for(self, logical_names: list[str],
                t: float | None = None) -> EpochMap:
        t = time.time() if t is None else t
        epoch = self._epoch_at(t)
        return EpochMap(
            epoch=epoch,
            mapping={n: self._ephemeral(n, epoch) for n in logical_names},
            valid_until=(epoch + 1) * self.epoch_seconds,
        )

    def resolve(self, ephemeral_name: str, logical_names: list[str],
                t: float | None = None) -> str | None:
        """Reverse lookup for key-holding services. Stale names -> None."""
        m = self.map_for(logical_names, t)
        for logical, eph in m.mapping.items():
            if hmac.compare_digest(eph, ephemeral_name):
                return logical
        return None
