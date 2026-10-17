# Self-Improvement Governance

The HARD loop (`aegis/self_improvement/hard_framework.py`) mutates the
system: it learns new detector signatures from observed bypasses. In a
regulated (BFSI) deployment, a system that changes itself is a compliance
surface, not a feature. This document defines the guardrails.

## 1. What HARD may and may not change

| Allowed | Not allowed |
| --- | --- |
| Add a signature to the local-sequence-alignment detector | Modify a `CapabilityContract` |
| Adjust detector weights within a bounded range | Change `deny_unlisted`, prohibitions, or approval flags |
| Cluster bypasses and extract n-grams | Touch the `ReferenceMonitor`, `AuditLog`, or signer |
| | Change latency budgets or fail-closed policy |

The containment boundary (contracts + monitor) is **immutable by the loop**.
HARD can only sharpen the *detection* layer, never relax the *enforcement*
layer.

## 2. Approval gate

Every HARD-evolved signature must pass the same validation gate as any other
change:

1. **Observe** — run the adversarial suite; collect bypasses.
2. **Analyze** — cluster and extract candidate signatures.
3. **Evolve** — stage the candidate (not applied yet).
4. **Validate** — re-run regression on the held-out set; the change is
   accepted only if security improves **without** raising the false-positive
   rate above the gate (`max_fp_rate`).
5. **Attest** — a human (or a separate approval service) signs the
   accept/reject decision; the signature is appended to the audit log.

`HardReport.generalization_gap` is the number a BFSI buyer should ask for:
it exposes whether the loop is overfitting to the training corpus.

## 3. Traceability

- Every accepted signature is recorded in the audit log with the candidate
  source, the validation metrics, and the approver.
- The loop is constrained by the same `ReferenceMonitor` it feeds: it has no
  execution path to the `ExecutorAgent` and cannot mint capability tokens.
- A rollback path exists: `Validate` rejects the change if the regression
  gate fails, leaving the previous detector state intact.

## 4. Production requirements (not yet implemented)

- **Human-in-the-loop approval** for signature promotion (currently the loop
  auto-accepts on gate pass in the reference build).
- **Shadow mode** — run the loop in shadow for N cycles and compare against
  the frozen baseline before enabling it in production.
- **Signed model registry** — version and sign each detector snapshot so an
  auditor can reconstruct "what was running when."

## 5. BFSI pilot gate

Do not enable HARD in a BFSI pilot until items in §4 are implemented and the
loop's accept/reject decisions are themselves attested by an independent
signer.
