# ADR 0001: Ed25519 as the default attestation signer

- Status: accepted
- Date: 2026-10-12

## Context

Attestations must be signed so a decision cannot be forged or repudiated.
HMAC is fast and stdlib-only but requires a shared secret; asymmetric signing
lets auditors verify with a public key only.

## Decision

`aegis.core.asymmetric.Ed25519Signer` is the default signer when the optional
`cryptography` package is installed; `HmacSigner` remains the stdlib fallback.
Auditors receive only the 32-byte public key via `Ed25519Verifier`, which has
no signing capability.

## Consequences

- Non-repudiation: a verifier can confirm a signature without the ability to
  forge one.
- Requires the optional `cryptography` dependency (documented in
  `requirements.txt`).
- Key rotation is an operational concern (see `docs/runbooks/key-rotation.md`).
