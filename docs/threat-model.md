# Aegis Threat Model

Status: living document · Owner: security · Review cadence: quarterly or on
architecture change.

Every control in Aegis should trace back to a threat in this document. If a
control has no threat, it is either performative or undocumented; if a threat
has no control, it is an open risk.

## 1. System under analysis

```text
untrusted input
   │  (docs, emails, tool output, chat)
   ▼
SemanticGateway ──► ReaderAgent ──► ReferenceMonitor ──► ExecutorAgent
   (Pillar 2)        (0 tools)       (contract + token)    (tools)
        │                                  │
        └──────── EventBus / AuditLog / Attestation / Merkle ──► evidence
```

Trust zones:

| Zone | Components | Trust level |
| --- | --- | --- |
| Untrusted | external documents, tool output, chat, feeds | none |
| Model-facing | `ReaderAgent`, `SemanticGateway` detectors | untrusted (may be fooled) |
| Enforcement | `ReferenceMonitor`, `CapabilityContract` | trusted core |
| Side-effect | `ExecutorAgent`, registered tools | trusted, gated |
| Evidence | `AuditLog`, `Attestation`, `MerkleLog` | trusted, tamper-evident |
| Infra | KMS/HSM, secrets, storage, network | trusted dependencies |

**Trust boundary #1** — between the model-facing zone and the enforcement
zone. A fully compromised `ReaderAgent` must not be able to mint authority.
**Trust boundary #2** — between enforcement and side effects. No action
executes without a valid, single-use, contract-bound token.

## 2. Adversary capabilities (assumed)

| Capability | Assumed? | Rationale |
| --- | --- | --- |
| Craft arbitrary prompt-injection payloads | yes | OWASP LLM01 |
| Embed attacks in tool output / documents | yes | indirect injection |
| Obfuscate (homoglyphs, leetspeak, zero-width, encoding) | yes | LLM01 evasion |
| Fully compromise the LLM (ReaderAgent) | yes | the core thesis |
| Observe public network traffic | yes | assume no transport secrecy |
| Replay captured tokens/attestations | yes | token replay |
| Compromise the enforcement core (ReferenceMonitor) | **no** | out of scope — that is the TCB |
| Compromise KMS/HSM | **no** | out of scope — hardware root of trust |
| Physical access to the host | **no** | out of scope |

## 3. STRIDE analysis

| # | Threat | Property | Control | Status |
| --- | --- | --- | --- | --- |
| S1 | Attacker spoofs an admin/authority instruction | Spoofing | `ReferenceMonitor` ignores identity claims in payload; authority comes only from contracts + tokens | done |
| S2 | Attacker spoofs a capability token | Spoofing | HMAC/Ed25519-signed single-use tokens; `redeem()` is atomic | done |
| T1 | Attacker tampers with a signed attestation | Tampering | canonical JSON payload + signature; `verify_attestation` | done |
| T2 | Attacker tampers with the audit log | Tampering | hash-chained `AuditLog` + RFC 9162 `MerkleLog` | done |
| T3 | Attacker tampers with a delegated contract | Tampering | strict attenuation (`delegation.py`): child ⊆ parent | done |
| R1 | Attacker replays a consumed token | Repudiation | nonce store + atomic redeem (at-most-once) | done |
| R2 | Insiders deny a decision happened | Repudiation | signed attestations + append-only audit | done |
| I1 | Attacker leaks secrets via prompt | Info disclosure | egress scanner (canary/secret/PII) | done |
| I2 | Attacker reads system prompt / API keys | Info disclosure | egress `scan_output()` blocks credential material | done |
| I3 | Attacker learns internal resource names | Info disclosure | MTAC polymorphic env rotates names per epoch | done |
| D1 | Attacker DoS via oversized payload | DoS | size caps + rate limiter (per-source + global) | done |
| D2 | Attacker DoS via nonce/queue growth | DoS | nonce pruning; bounded marker caps | done |
| D3 | Attacker DoS via slow-loris | DoS | socket timeouts; recommend proxy (Risk E) | partial |
| E1 | Attacker escalates a low-privilege action | Elevation | `deny_unlisted` default; prohibited actions deny | done |
| E2 | Attacker escalates via delegation | Elevation | delegation depth cap + bool-aware flag merge | done |

## 4. LINDDUN (privacy) analysis

| # | Threat | Control | Status |
| --- | --- | --- | --- |
| L1 | Linking records to a subject | egress PII redaction (sparse PII redacted, bulk blocked) | done |
| L2 | Identifying individuals in logs | audit logs record actions, not raw payloads | done |
| L3 | Non-repudiation of decisions | signed attestations | done |
| L4 | Detecting data exfiltration | egress scanner + taint tracker | done |
| L5 | Unawareness of data flows | dashboard event stream + compliance map | done |

## 5. Out-of-scope assumptions (explicit)

- The `ReferenceMonitor`, `CapabilityContract`, and `AuditLog` form the
  trusted computing base; their compromise is out of scope.
- KMS/HSM and the host OS are trusted.
- mTLS service-to-service encryption is a deployment concern (Risk E), not
  enforced in code.
- The BB84 module is educational; production key establishment is PQC
  (`aegis.core.asymmetric.PqcKeyExchange`).

## 6. Traceability

| Control | Threat(s) |
| --- | --- |
| fail-closed gateway | D1, D2, I1 |
| `DEFER_HUMAN` + approval queue | E1, S1 |
| hash-chain + Merkle | T2, R2 |
| signed attestations | T1, R2, L3 |
| strict delegation | T3, E2 |
| single-use tokens | S2, R1 |
| egress scanning | I1, I2, L1, L5 |
| polymorphic env | I3 |
