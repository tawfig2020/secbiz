"""Smoke test for Agent Vault — run directly, no pytest needed.

    python -m agent_vault.smoke_test
"""
from __future__ import annotations

from aegis.core import Money

from agent_vault import AgentVault


def main() -> None:
    vault = AgentVault()

    # 1. Prohibited action is denied.
    r = vault.evaluate_action("export_customer_pii", {"scope": "all"})
    assert r["decision"] == "DENY", r

    # 2. Human-gated transfer is deferred, never auto-executed.
    r = vault.evaluate_action(
        "wire_transfer",
        {"amount": Money.from_minor(500_000, "USD"), "beneficiary": "ACC-100"})
    assert r["decision"] == "DEFER_HUMAN", r

    # 3. Over-limit transfer is denied by the contract constraint.
    r = vault.evaluate_action(
        "wire_transfer",
        {"amount": Money.from_minor(4_500_000, "USD"), "beneficiary": "ACC-100"})
    assert r["decision"] == "DENY", r

    # 4. Legitimate read is allowed and executes.
    r = vault.mediate(
        "read_transaction", {"amount": Money.from_minor(120_000, "USD")})
    assert r["decision"] == "ALLOW", r
    assert r["executed"] is True, r

    # 5. Every attestation verifies offline.
    for a in vault.attestations():
        assert vault.verify_attestation(a), a

    # 6. Audit chain is intact.
    assert vault.audit.verify()

    print("Agent Vault smoke test: ALL PASS")


if __name__ == "__main__":
    main()
