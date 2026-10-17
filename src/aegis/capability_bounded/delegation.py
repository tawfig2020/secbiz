"""Delegation attenuation: closing the confused-deputy hole.

Without attenuation, an agent that can `spawn_subagent` can hand its full
capability contract to the child — the classic confused-deputy pattern
present in every major agentic framework. A prompt injection that
convinces agent A to spawn B then rides A's authority through B, and the
"provable containment" claim only held at the first hop.

`delegate_contract()` enforces strict attenuation:

  - child permitted actions must be a SUBSET of the parent's
    (a capability the parent lacks cannot be created by delegation)
  - constraints only ever TIGHTEN: enums intersect, numeric bounds move
    inward, human-approval/evidence flags can be added but not removed
  - prohibited_actions is the UNION — a child can never un-prohibit
  - delegation_depth increments and is capped at MAX_DELEGATION_DEPTH

Every successful delegation should be minted as an attestation linking
parent -> child (see ReferenceMonitor.delegate) so provenance is
preserved in the audit chain.
"""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Mapping

from .capability_contract import (
    CapabilityContract,
    PermittedAction,
    _FLAG_KEYS,
)

MAX_DELEGATION_DEPTH = 4


class DelegationError(Exception):
    """Raised when a requested child scope exceeds the parent's authority."""


def _merge_flag(parent_v: Any, child_v: Any) -> Any:
    """Boolean-ish flags tighten monotonically: once required, always
    required downstream. auto_block_threshold tightens downward."""
    if parent_v is None:
        return child_v
    if child_v is None:
        return parent_v
    # bool is a subclass of int: without this guard min(True, False) == False
    # would let a child DROP a parent's requires_human_approval.
    if isinstance(parent_v, bool) or isinstance(child_v, bool):
        return bool(parent_v) or bool(child_v)
    if isinstance(parent_v, (int, float)) and isinstance(child_v, (int, float)):
        return min(parent_v, child_v)
    return bool(parent_v) or bool(child_v)


def _merge_numeric(bound: str, parent_v: Any, child_v: Any) -> Any:
    """max_* tightens downward; min_* tightens upward."""
    vals = [v for v in (parent_v, child_v) if isinstance(v, (int, float))]
    if not vals:
        return parent_v if parent_v is not None else child_v
    return min(vals) if bound == "max" else max(vals)


def _merge_enum(parent_v: Any, child_v: Any, key: str) -> frozenset:
    """Enum allowlists intersect; an empty intersection means the child
    asked for values the parent never granted."""
    p = set(parent_v) if parent_v is not None else None
    c = set(child_v) if child_v is not None else None
    if p is None:
        merged = c
    elif c is None:
        merged = p
    else:
        merged = p & c
    if not merged:
        raise DelegationError(
            f"constraint {key!r}: child values {sorted(c or [])} are outside "
            f"the parent's allowed set {sorted(p or [])}")
    return frozenset(merged)


def _merge_structured(parent_v: Mapping, child_v: Mapping,
                      key: str) -> dict:
    """Structured rules merge per-field: max_len -> min, enum -> intersect,
    pattern must be identical if both sides specify one (ambiguous
    tightening is refused rather than guessed)."""
    merged: dict[str, Any] = {}
    for field_key in set(parent_v) | set(child_v):
        pv, cv = parent_v.get(field_key), child_v.get(field_key)
        if pv is None:
            merged[field_key] = cv
            continue
        if cv is None:
            merged[field_key] = pv
            continue
        if field_key == "max_len":
            merged[field_key] = min(pv, cv)
        elif field_key == "enum":
            inter = set(pv) & set(cv)
            if not inter:
                raise DelegationError(
                    f"constraint {key!r}: child enum outside parent's")
            merged[field_key] = sorted(inter)
        elif field_key == "pattern":
            if pv != cv:
                raise DelegationError(
                    f"constraint {key!r}: child pattern {cv!r} diverges "
                    f"from parent {pv!r}")
            merged[field_key] = pv
        else:
            merged[field_key] = pv
    return merged


def _intersect_constraints(parent: Mapping[str, Any],
                           child: Mapping[str, Any]) -> dict[str, Any]:
    """Tightening-only constraint merge. Anything the parent enforces is
    inherited; anything the child adds is kept if it narrows the parent."""
    merged: dict[str, Any] = {}
    for key in set(parent) | set(child):
        pv, cv = parent.get(key), child.get(key)
        if key in _FLAG_KEYS:
            merged[key] = _merge_flag(pv, cv)
            continue
        m = re.fullmatch(r"(max|min)_(.+)", key)
        if m:
            merged[key] = _merge_numeric(m.group(1), pv, cv)
            continue
        if isinstance(pv, Mapping) or isinstance(cv, Mapping):
            if isinstance(pv, Mapping) and isinstance(cv, Mapping):
                merged[key] = _merge_structured(pv, cv, key)
            else:
                # type mismatch: parent's rule stands (it is authoritative)
                merged[key] = pv if pv is not None else cv
            continue
        if isinstance(pv, (list, tuple, frozenset)) or \
                isinstance(cv, (list, tuple, frozenset)):
            merged[key] = _merge_enum(pv, cv, key)
            continue
        merged[key] = pv if pv is not None else cv
    return merged


def _merge_audit(parent: Mapping[str, Any],
                 child: Mapping[str, Any]) -> dict[str, Any]:
    """Audit duties only ever tighten: required flags stay required and
    retention never shrinks below the parent's."""
    merged = dict(child)
    for key, pv in parent.items():
        cv = merged.get(key)
        if isinstance(pv, bool):
            merged[key] = pv or bool(cv)
        elif isinstance(pv, (int, float)):
            merged[key] = max(pv, cv) if isinstance(cv, (int, float)) \
                and not isinstance(cv, bool) else pv
        else:
            merged.setdefault(key, pv)
    return merged


def delegate_contract(parent: CapabilityContract,
                      requested: CapabilityContract,
                      max_depth: int = MAX_DELEGATION_DEPTH
                      ) -> CapabilityContract:
    """Return a child contract strictly weaker than `parent`.

    Raises DelegationError if the child asks for an action the parent
    lacks, requests a constraint outside the parent's grant, or the
    depth cap is exceeded.
    """
    depth = parent.delegation_depth + 1
    if depth > max_depth:
        raise DelegationError(
            f"delegation depth {depth} exceeds cap {max_depth}")

    child_actions: dict[str, PermittedAction] = {}
    for name, spec in requested.permitted_actions.items():
        parent_spec = parent.permitted_actions.get(name)
        if parent_spec is None:
            raise DelegationError(
                f"child cannot hold {name!r}: parent contract "
                f"{parent.contract_id!r} does not permit it")
        child_actions[name] = PermittedAction(
            name=name,
            constraints=_intersect_constraints(parent_spec.constraints,
                                               spec.constraints))

    return replace(
        requested,
        permitted_actions=child_actions,
        prohibited_actions=(frozenset(parent.prohibited_actions)
                            | frozenset(requested.prohibited_actions)),
        audit_requirements=_merge_audit(parent.audit_requirements,
                                        requested.audit_requirements),
        # A child may never be more permissive than its parent.
        deny_unlisted=parent.deny_unlisted or requested.deny_unlisted,
        delegation_depth=depth,
    )
