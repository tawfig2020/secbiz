"""Export the held-out adversarial corpus for independent validation.

The 3.1% bypass rate reported by `validate.py` is measured on an in-house
corpus. Before anyone relies on that number, the held-out attack scenarios
(validation + test splits, never seen by HARD's training) must be replayed
against the gateway by an independent red team or on an external dataset.

Usage:
    python export_heldout.py [--out heldout.jsonl] [--target 520]

Each JSON line: {id, category, payload, mutation, host, expect_block, split}
"""
from __future__ import annotations

import argparse
import json
import sys

from aegis.evaluation import generate_corpus
from aegis.evaluation.corpus_registry import CorpusRegistry


def export(path: str, target: int) -> int:
    registry = CorpusRegistry()
    corpus = generate_corpus(target=target, registry=registry)
    rows = []
    for sc in (*corpus.validation, *corpus.test, *corpus.benign):
        split = registry.split_for(sc.id)
        rows.append({
            "id": sc.id,
            "category": sc.category,
            "payload": sc.payload,
            "mutation": sc.mutation,
            "host": sc.host,
            "expect_block": sc.expect_block,
            "split": split,
        })
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="heldout.jsonl")
    ap.add_argument("--target", type=int, default=520)
    args = ap.parse_args()
    n = export(args.out, args.target)
    print(f"wrote {n} held-out scenarios to {args.out}")
    print("replay each payload through SemanticGateway.scan() and compare "
          "the verdict against expect_block; report the bypass rate "
          "independently of validate.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
