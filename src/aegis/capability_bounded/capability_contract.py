"""Capability contract: spec section 6.2 schema.

JSON shape:

    {
      "contract_id": "aegis.financial.transaction.v1",
      "permitted_actions": [
        {"action": "read_transaction",
         "constraints": {"max_amount": 10000,
                         "currency": ["USD", "EUR"],
                         "requires_human_approval": false}}
      ],
      "prohibited_actions": ["execute_transfer", "export_customer_pii"],
      "audit_requirements": {"log_every_action": true, "retention_days": 2555}
    }

Constraint keys:
  requires_human_approval : bool   -> DEFER_HUMAN verdict
  requires_evidence       : bool   -> params must carry non-empty "evidence"
  auto_block_threshold    : float  -> advisory metadata for callers
  max_<param> / min_<param>        -> numeric bound on that param
  <param>: [list]                  -> enum allowlist for that param
  <param>: {"pattern","max_len"}   -> string constraints
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from aegis.core.money import Money

_FLAG_KEYS = {"requires_human_approval", "requires_evidence",
              "auto_block_threshold"}


@dataclass(frozen=True)
class PermittedAction:
    name: str
    constraints: Mapping[str, Any] = field(default_factory=dict)

    @property
    def requires_human_approval(self) -> bool:
        return bool(self.constraints.get("requires_human_approval"))


@dataclass(frozen=True)
class CapabilityContract:
    contract_id: str
    permitted_actions: Mapping[str, PermittedAction]
    prohibited_actions: frozenset = frozenset()
    audit_requirements: Mapping[str, Any] = field(default_factory=dict)
    deny_unlisted: bool = True          # not permitted => denied
    delegation_depth: int = 0           # how many delegations produced this

    # -- loading ---------------------------------------------------------
    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CapabilityContract":
        permitted = {}
        for entry in d.get("permitted_actions", []):
            spec = PermittedAction(entry["action"],
                                   entry.get("constraints", {}))
            permitted[spec.name] = spec
        return cls(
            contract_id=d["contract_id"],
            permitted_actions=permitted,
            prohibited_actions=frozenset(d.get("prohibited_actions", [])),
            audit_requirements=d.get("audit_requirements", {}),
            delegation_depth=int(d.get("delegation_depth", 0)),
        )

    @classmethod
    def from_json(cls, s: str) -> "CapabilityContract":
        return cls.from_dict(json.loads(s))


def _check_param(name: str, rule: Any, value: Any) -> str | None:
    """Evaluate one constraint entry against a param value."""
    if isinstance(rule, (list, tuple, frozenset)):      # enum allowlist
        if value not in rule:
            return f"{value!r} not in allowed set {list(rule)}"
        return None
    if isinstance(rule, Mapping):                        # structured rule
        if "pattern" in rule and isinstance(value, str):
            if not re.fullmatch(rule["pattern"], value):
                return f"does not match pattern {rule['pattern']!r}"
        if "max_len" in rule and isinstance(value, str):
            if len(value) > rule["max_len"]:
                return f"exceeds max_len {rule['max_len']}"
        if "enum" in rule and value not in rule["enum"]:
            return f"{value!r} not in enum {rule['enum']}"
        return None
    return None                                          # advisory key


def validate(contract: CapabilityContract, action: str,
             params: Mapping[str, Any]) -> list[str]:
    """Constraint validation. Returns error strings (empty = permitted)."""
    if action in contract.prohibited_actions:
        return [f"action {action!r} is PROHIBITED by contract "
                f"{contract.contract_id}"]

    spec = contract.permitted_actions.get(action)
    if spec is None:
        if contract.deny_unlisted:
            return [f"action {action!r} is not permitted by contract "
                    f"{contract.contract_id}"]
        return []

    errors: list[str] = []
    for key, rule in spec.constraints.items():
        if key in _FLAG_KEYS:
            if key == "requires_evidence" and rule:
                if not params.get("evidence"):
                    errors.append("requires_evidence: params['evidence'] missing")
            continue
        # Money-aware bounds: max_amount_minor / min_amount_minor apply when
        # the param is a Money value; comparison is exact (integer cents).
        m = re.fullmatch(r"(max|min)_(.+)_minor", key)
        if m and isinstance(params.get(m.group(2)), Money):
            v = params[m.group(2)]
            minor = v.to_minor()
            if m.group(1) == "max" and minor > rule:
                errors.append(f"param {m.group(2)!r}: {v} above max "
                              f"{rule} minor units")
            if m.group(1) == "min" and minor < rule:
                errors.append(f"param {m.group(2)!r}: {v} below min "
                              f"{rule} minor units")
            continue
        if key == "currency" and isinstance(params.get("amount"), Money):
            if params["amount"].currency not in rule:
                errors.append(f"currency {params['amount'].currency!r} "
                              f"not in allowed set {list(rule)}")
            continue
        m = re.fullmatch(r"(max|min)_(.+)", key)
        if m:
            bound, param = m.group(1), m.group(2)
            v = params.get(param)
            if v is not None and isinstance(v, (int, float)):
                if bound == "max" and v > rule:
                    errors.append(f"param {param!r}: {v!r} above max {rule}")
                if bound == "min" and v < rule:
                    errors.append(f"param {param!r}: {v!r} below min {rule}")
            continue
        err = _check_param(key, rule, params.get(key))
        if err:
            errors.append(f"param {key!r}: {err}")
    return errors
