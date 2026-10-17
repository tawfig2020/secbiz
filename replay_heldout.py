"""Independent held-out replay (Risk I measurement).

Replays the exported held-out corpus through `SemanticGateway.scan()` and
reports the bypass rate and false-positive rate *without* using the
`validate.py` regression path. This is the honest in-house measurement; it is
NOT a substitute for an external red-team engagement.

Usage:
    python export_heldout.py --out heldout.jsonl --target 520
    python replay_heldout.py heldout.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys

from aegis.semantic_gateway import SemanticGateway, Verdict


def replay(path: str) -> dict:
    gateway = SemanticGateway()
    total = 0
    bypass = 0
    fp = 0
    blocked_expected = 0
    allowed_expected = 0

    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            expect_block = bool(row.get("expect_block", True))
            # Independent per-payload evaluation: a unique source_id prevents
            # the stateful fatigue tracker from correlating unrelated corpus
            # entries (which would inflate false positives).
            verdict = gateway.scan(row["payload"], source_id=row["id"]).verdict
            total += 1
            if expect_block:
                blocked_expected += 1
                if verdict is not Verdict.BLOCK:
                    bypass += 1
            else:
                allowed_expected += 1
                if verdict is Verdict.BLOCK:
                    fp += 1

    return {
        "total": total,
        "blocked_expected": blocked_expected,
        "allowed_expected": allowed_expected,
        "bypass": bypass,
        "false_positive": fp,
        "bypass_rate": bypass / blocked_expected if blocked_expected else 0.0,
        "fp_rate": fp / allowed_expected if allowed_expected else 0.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="held-out JSONL corpus")
    args = ap.parse_args()

    r = replay(args.path)
    print(f"total={r['total']} expect_block={r['blocked_expected']} "
          f"expect_allow={r['allowed_expected']}")
    print(f"bypass={r['bypass']} ({r['bypass_rate']:.1%})  "
          f"false_positive={r['false_positive']} ({r['fp_rate']:.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
