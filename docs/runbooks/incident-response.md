# Incident Response Runbook

## 1. Triage

| Signal | Meaning | First action |
| --- | --- | --- |
| `aegis_gateway_scan_total{verdict="BLOCK"}` spike | active attack or detector regression | pull correlation IDs from logs |
| `aegis_decision_total{decision="DENY"}` spike | contract enforcement firing | check the denied actions |
| `aegis_gateway_latency_ms` p99 > budget | DoS or detector slowdown | check rate limiter + queue depth |
| `aegis_approval_queue_depth` growing | deferred work not being resolved | page the approver on-call |

## 2. Containment

1. Confirm the gateway is fail-closed: every error path returns BLOCK, never
   ALLOW (`docs/adr/0004-fail-closed.md`).
2. If a detector is raising, the gateway already fails closed; isolate the
   source and redeploy.
3. If the approval queue is backing up, do **not** auto-approve — route to a
   human (four-eyes is the control).

## 3. Investigation

- Every decision has a signed attestation and an audit-log entry; query by
  `correlation_id` to reconstruct the request path.
- The audit log is hash-chained; `AuditLog.verify()` proves integrity.
- The Merkle log provides inclusion proofs for external auditors.

## 4. Recovery

- Rotate the signer key if a signing key is suspected compromised
  (`docs/runbooks/key-rotation.md`).
- Re-run `python validate.py` after any fix; the regression gate must pass.
- Post-incident, update `docs/threat-model.md` if a new threat was observed.

## 5. Escalation

| Severity | Criteria | Response |
| --- | --- | --- |
| SEV1 | containment bypass (ALLOW on attack) | page security lead + halt rollout |
| SEV2 | fail-closed outage (all BLOCK) | page on-call, restore availability |
| SEV3 | detector regression / FP spike | triage within business hours |
