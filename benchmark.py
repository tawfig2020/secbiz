"""Internal validation benchmark: baseline vs Aegis + HARD + test suite.

Run: python benchmark.py

Produces a repeatable report (human-readable + benchmark_report.json) that
proves containment against the industry baseline (keyword guardrails) and
measures HARD self-improvement generalization on a held-out set.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

from aegis.capability_bounded import Action
from aegis.evaluation import (
    BaselineGuardedAgent,
    KeywordGuardrail,
    generate_suite,
    run_regression,
)
from aegis.self_improvement import HardFramework
from aegis.semantic_gateway import SemanticGateway


def run_test_suite() -> dict:
    """Run the full unittest suite and parse the result."""
    start = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        capture_output=True, text=True)
    elapsed = time.time() - start
    ran = 0
    for line in (proc.stdout + proc.stderr).splitlines():
        if line.strip().startswith("Ran "):
            ran = int(line.strip().split()[1])
    return {"ran": ran, "passed": proc.returncode == 0,
            "seconds": round(elapsed, 2)}


def baseline_metrics(suite) -> dict:
    """Industry status quo: keyword guardrail + ambient-authority tool call."""
    agent = BaselineGuardedAgent(
        model_fn=lambda text: Action("export_all_data", {}),
        guardrail=KeywordGuardrail())
    agent.register_tool("export_all_data", lambda: "ALL RECORDS")

    attacks = [s for s in suite if s.expect_block]
    benign = [s for s in suite if not s.expect_block]
    bypass = sum(1 for s in attacks if agent.process(s.payload).executed)
    fp = sum(1 for s in benign if not agent.process(s.payload).executed)
    return {
        "attacks": len(attacks),
        "bypass_rate": round(bypass / len(attacks), 4) if attacks else 0.0,
        "benign_blocked_rate": round(fp / len(benign), 4) if benign else 0.0,
    }


def main() -> None:
    suite = generate_suite(target=520)
    gateway = SemanticGateway()

    print("=" * 64)
    print("  AEGIS INTERNAL VALIDATION BENCHMARK")
    print("=" * 64)

    print("\n[1] Test suite")
    tests = run_test_suite()
    status = "PASS" if tests["passed"] else "FAIL"
    print(f"    {tests['ran']} tests, {status} ({tests['seconds']}s)")

    print("\n[2] Containment: baseline vs Aegis (same corpus)")
    base = baseline_metrics(suite)
    reg = run_regression(gateway, suite)
    m = reg.metrics
    print(f"    baseline (keyword guardrail): bypass {base['bypass_rate']:.1%}, "
          f"benign-blocked {base['benign_blocked_rate']:.1%}")
    print(f"    Aegis   (gateway + monitor) : bypass {m.bypass_rate:.1%}, "
          f"FP {m.fp_rate:.1%}, detection {m.detection_rate:.1%}, "
          f"p50 {m.p50_ms:.2f}ms, p99 {m.p99_ms:.2f}ms")

    print("\n[3] HARD self-improvement (held-out generalization)")
    hard = HardFramework(gateway, suite=suite).cycle()
    print(f"    bypass before -> after : {hard.bypass_before:.1%} -> "
          f"{hard.bypass_after:.1%}")
    print(f"    held-out before -> after: {hard.heldout_bypass_before:.1%} -> "
          f"{hard.heldout_bypass_after:.1%}")
    print(f"    generalization gap     : {hard.generalization_gap:.1%}")
    print(f"    accepted               : {hard.accepted}")

    report = {
        "tests": tests,
        "baseline": base,
        "aegis": {
            "bypass_rate": m.bypass_rate,
            "fp_rate": m.fp_rate,
            "detection_rate": m.detection_rate,
            "p50_ms": m.p50_ms,
            "p95_ms": m.p95_ms,
            "p99_ms": m.p99_ms,
        },
        "hard": {
            "bypass_before": hard.bypass_before,
            "bypass_after": hard.bypass_after,
            "heldout_bypass_before": hard.heldout_bypass_before,
            "heldout_bypass_after": hard.heldout_bypass_after,
            "generalization_gap": hard.generalization_gap,
            "accepted": hard.accepted,
        },
    }
    with open("benchmark_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\nWrote benchmark_report.json")


if __name__ == "__main__":
    main()
