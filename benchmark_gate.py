"""Benchmark regression gate: fail CI if containment metrics regress.

Runs `benchmark.py` (which writes `benchmark_report.json`) and compares the
reported bypass/FP rates against the committed baseline. A regression in
containment (higher bypass) or false positives (higher FP) fails the gate.

Usage:
    python benchmark_gate.py [--max-bypass 0.05] [--max-fp 0.01]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT = ROOT / "benchmark_report.json"


def _run_benchmark() -> None:
    proc = subprocess.run([sys.executable, "benchmark.py"],
                          cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout + proc.stderr)
        sys.exit("benchmark.py failed")


def _load_report() -> dict:
    if not REPORT.exists():
        sys.exit("benchmark_report.json not found; run benchmark.py first")
    return json.loads(REPORT.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-bypass", type=float, default=0.05)
    ap.add_argument("--max-fp", type=float, default=0.01)
    args = ap.parse_args()

    _run_benchmark()
    report = _load_report()

    # The report shape varies; locate the top-level metrics defensively.
    bypass = report.get("bypass_rate", report.get("bypass"))
    fp = report.get("fp_rate", report.get("false_positive_rate"))
    if bypass is None or fp is None:
        print(f"report keys: {sorted(report)}")
        sys.exit("could not locate bypass/fp metrics in benchmark_report.json")

    print(f"bypass {float(bypass):.1%} (max {args.max_bypass:.1%}), "
          f"FP {float(fp):.1%} (max {args.max_fp:.1%})")
    if float(bypass) > args.max_bypass or float(fp) > args.max_fp:
        print("RESULT: FAIL — benchmark regression")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
