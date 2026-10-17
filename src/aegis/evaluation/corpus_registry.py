"""Corpus registry: tracks which adversarial scenarios live in which
disjoint set — TRAIN (fed to HARD's Observe phase), VALIDATION (held-out
accept/reject gate), TEST (locked; headline metrics only, rotated
quarterly).

This exists to kill train/test contamination: if HARD evolves a signature
against a case, that case is 'burned' — it transitions TEST -> TRAIN and
the registry logs the move with a timestamp so headline metrics stay
honest.

Persisting to corpus_registry.json is optional; pass a path to keep the
ledger across runs.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Iterable

SPLITS = ("train", "validation", "test")

# Deterministic split: sha256(scenario_id) mod 5 -> 0,1,2=train 3=val 4=test
_BUCKETS = {0: "train", 1: "train", 2: "train", 3: "validation", 4: "test"}


def assign_split(scenario_id: str) -> str:
    bucket = int(hashlib.sha256(scenario_id.encode()).hexdigest(), 16) % 5
    return _BUCKETS[bucket]


class CorpusRegistry:
    """scenario_id -> split ledger with transition history."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._entries: dict[str, dict] = {}
        if self._path and self._path.exists():
            self._entries = json.loads(self._path.read_text())

    # -- assignment --------------------------------------------------------
    def split_for(self, scenario_id: str) -> str:
        """Existing assignment if recorded, else deterministic hash."""
        entry = self._entries.get(scenario_id)
        if entry:
            return entry["split"]
        return assign_split(scenario_id)

    def register(self, scenario_ids: Iterable[str]) -> None:
        """Persist assignments for ids that don't have one yet."""
        for sid in scenario_ids:
            if sid not in self._entries:
                self._entries[sid] = {
                    "split": self.split_for(sid),
                    "set_at": time.time(),
                    "transitions": [],
                }
        self._save()

    # -- lifecycle ---------------------------------------------------------
    def burn(self, scenario_id: str, reason: str = "") -> None:
        """A test case consumed by evolution is retired to TRAIN. The move
        is logged so headline metrics exclude burned cases."""
        entry = self._entries.get(scenario_id)
        if entry is None:
            self.register([scenario_id])
            entry = self._entries[scenario_id]
        old = entry["split"]
        if old == "train":
            return
        entry["split"] = "train"
        entry["transitions"].append(
            {"from": old, "to": "train", "ts": time.time(),
             "reason": reason})
        self._save()

    # -- inspection --------------------------------------------------------
    def stats(self) -> dict[str, int]:
        counts = {s: 0 for s in SPLITS}
        for e in self._entries.values():
            counts[e["split"]] += 1
        return counts

    def transitions(self) -> list[dict]:
        out = []
        for sid, e in self._entries.items():
            for t in e["transitions"]:
                out.append({"scenario_id": sid, **t})
        return out

    def _save(self) -> None:
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._entries, indent=2))
