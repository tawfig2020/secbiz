# ADR 0004: Fail-closed by default

- Status: accepted
- Date: 2026-10-12

## Context

A security boundary that fails open (returns ALLOW on error) is worse than no
boundary. The gateway and monitor must never fabricate an ALLOW verdict when
a detector raises, a dependency is unavailable, or a latency budget is blown.

## Decision

- `SemanticGateway.scan()` returns BLOCK on any internal detector error.
- `ReferenceMonitor` defaults `deny_unlisted=True`: an action not explicitly
  permitted is denied.
- Latency-budget policy defaults to `fail_closed` for the strictest vertical.
- `InfraError` is marked `is_safe_to_abort` (our fault), while
  `DomainError`/`PolicyError`/`ProtocolError` are `is_safe_to_deny` (the
  request's fault).

## Consequences

- Availability can be reduced under failure, which is the intended trade-off
  for a security product.
- Chaos tests (`tests/test_chaos.py`) prove fail-closed under partial failure.
