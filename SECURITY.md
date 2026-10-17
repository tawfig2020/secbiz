# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x (reference implementation) | yes |

## Reporting a vulnerability

Do **not** open a public issue. Email the security team directly:

- `security@aegis.example` (replace with the real alias before public release)

Include:

1. A description of the vulnerability and its impact.
2. Steps to reproduce (a minimal payload or test case).
3. The affected component (`semantic_gateway`, `capability_bounded`, `core`, …).
4. Any proposed mitigation.

We respond within 5 business days and acknowledge receipt within 48 hours.
We will not disclose the issue publicly until a fix is released and a
coordinated disclosure window has passed.

## Scope

In scope: prompt-injection containment, capability-contract enforcement,
attestation/audit integrity, egress scanning, and the HTTP command center.

Out of scope: the BB84 simulation (educational), demo scripts, and
deployment infrastructure not yet provisioned (see `docs/operations.md`).

## Security model

The trusted computing base is `aegis.core` + `aegis.capability_bounded`
(`ReferenceMonitor`, `CapabilityContract`, `AuditLog`, `Attestation`).
A vulnerability that lets a compromised `ReaderAgent` mint authority, replay
a token, or tamper with the audit chain is critical. See
`docs/threat-model.md` for the full model.
