# ADR 0002: RFC 9162 Merkle transparency log

- Status: accepted
- Date: 2026-10-12

## Context

The hash-chained audit log detects tampering but does not scale to efficient
inclusion proofs or independent monitoring. A transparency log lets a third
party verify that a given decision was included without trusting the operator.

## Decision

`aegis.core.merkle.MerkleLog` implements an RFC 9162-style append-only tree
with inclusion proofs. The audit log remains the authoritative event stream;
the Merkle log is the tamper-evident, externally-verifiable projection.

## Consequences

- Inclusion proofs are O(log n) and verify against a single root.
- Any single-leaf mutation changes the root (property-tested).
- The tree is in-memory in the reference build; durable anchoring is a
  production gap.
