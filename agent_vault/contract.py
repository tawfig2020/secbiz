"""BFSI capability contract for the Agent Vault prototype.

The contract is the *boundary*: it declares what a banking agent may do,
what it may never do, and what requires a human in the loop. It is enforced
by the ReferenceMonitor outside the model — a hijacked agent cannot edit it.
"""
from __future__ import annotations

CONTRACT_ID = "aegis.bfsi.agent.v1"

CONTRACT_JSON = {
    "contract_id": CONTRACT_ID,
    "permitted_actions": [
        {
            "action": "read_transaction",
            "constraints": {
                "max_amount_minor": 1_000_000,   # $10,000.00 (exact cents)
                "currency": ["USD", "EUR", "GBP"],
            },
        },
        {
            "action": "summarize_document",
            "constraints": {"format": ["brief", "detailed"]},
        },
        {
            "action": "wire_transfer",
            "constraints": {
                "max_amount_minor": 1_000_000,   # $10,000.00 (exact cents)
                "beneficiary": ["ACC-100", "ACC-200"],
                "requires_human_approval": True,
            },
        },
    ],
    "prohibited_actions": [
        "execute_transfer",
        "modify_swift_message",
        "export_customer_pii",
    ],
    "audit_requirements": {"log_every_action": True, "retention_days": 2555},
}
