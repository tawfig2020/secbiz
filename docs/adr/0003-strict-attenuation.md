# ADR 0003: Strict capability attenuation

- Status: accepted
- Date: 2026-10-12

## Context

Delegation lets a parent contract grant a child contract. A child must never
be able to *widen* the parent's authority (e.g. raise a `max_amount`, drop a
`requires_human_approval` flag, or add a prohibited action).

## Decision

`aegis.capability_bounded.delegation.delegate_contract` enforces strict
attenuation: numeric bounds take the tighter value, allowlists intersect,
prohibitions union, and boolean flags OR together. A bool is treated as a
boolean, not as an `int` (a `bool` is a subclass of `int`, which previously
allowed a child to drop a parent's `requires_human_approval`).

## Consequences

- A compromised child contract cannot escalate beyond its parent.
- The bool/int guard is regression-tested (`tests/test_second_pass.py`).
- Property test asserts child scope ⊆ parent scope.
