"""CI/CD deploy gate (Phase 6): fail the build on any threshold violation.

Run: python validate.py
Exit code 0 = pass, 1 = fail.

Gates:
  1. Full unittest suite must pass.
  2. Security regression must pass (bypass <=5%, FP <=1%, p99 <=20ms).
"""
from __future__ import annotations

import subprocess
import sys

from aegis.evaluation import generate_suite, run_regression
from aegis.semantic_gateway import SemanticGateway


def _run_tests() -> tuple[bool, str]:
    # -t . makes unittest import tests as a package (tests/__init__.py).
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        capture_output=True, text=True)
    tail = (proc.stdout + proc.stderr)[-2000:]
    return proc.returncode == 0, tail


def main() -> None:
    failures: list[str] = []

    print("=" * 64)
    print("  AEGIS VALIDATION GATE (Phase 6)")
    print("=" * 64)

    print("\n[1] Test suite")
    ok, tail = _run_tests()
    print("    PASS" if ok else "    FAIL")
    if not ok:
        failures.append("test suite failed")
        print(tail)

    print("\n[2] Security regression gate")
    suite = generate_suite(target=520)
    gateway = SemanticGateway()
    reg = run_regression(gateway, suite)
    m = reg.metrics
    print(f"    bypass {m.bypass_rate:.1%}, FP {m.fp_rate:.1%}, "
          f"p50 {m.p50_ms:.2f}ms, p99 {m.p99_ms:.2f}ms")
    if reg.passed:
        print("    PASS")
    else:
        print("    FAIL")
        failures.append(f"regression gate: {reg.violations}")

    print("\n" + "=" * 64)
    if failures:
        print("  RESULT: FAIL")
        for f in failures:
            print(f"    - {f}")
        sys.exit(1)
    print("  RESULT: PASS — safe to deploy")
    sys.exit(0)


if __name__ == "__main__":
    main()
