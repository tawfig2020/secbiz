# Audit Log Retention & Archival

## Policy by regime

| Regime | Retention | Source |
| --- | --- | --- |
| MiFID II | 7 years (2555 days) | `bfsi.py` `retention_days` |
| HIPAA | 6 years | healthcare vertical |
| FedRAMP | 7 years (audit records) | government vertical |

## Implementation

- `CapabilityContract.audit_requirements.retention_days` declares the regime
  requirement per contract.
- The hash-chained `AuditLog` and `MerkleLog` are the tamper-evident store.
- Archival: export the chain (`AuditLog.render()`) and the Merkle root to
  immutable storage (WORM bucket) on a schedule; the root is the anchor.

## Verification

- `AuditLog.verify()` proves the in-process chain is intact.
- `MerkleLog.verify(proof, root)` proves a historical event was included.
- Retention compliance is checked by querying the earliest event timestamp
  against the declared `retention_days`.

## Gap

The reference build keeps the log in-memory or single-node SQLite. Production
requires a shared, replicated store (Risk B) and WORM archival.
