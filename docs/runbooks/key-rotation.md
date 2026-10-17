# Ed25519 Signer Key Rotation

## Policy

- Attestation signing keys rotate every **90 days** (or immediately on
  suspected compromise).
- Old public keys remain verifiable for the retention window so historical
  attestations still validate.

## Procedure

1. Generate a new key pair:
   ```python
   from aegis.core.asymmetric import Ed25519Signer
   signer = Ed25519Signer()
   # persist signer.private_key securely (KMS/HSM); publish signer.public_key
   ```
2. Deploy the new public key to verifiers (auditors, dashboard).
3. Re-sign the current audit-log head with the new key and record the
   rotation event in the audit log (signed by the *old* key).
4. Retire the old private key after the overlap window (≥ 1 retention period).

## KMS/HSM path

In production the private key never leaves the KMS/HSM; use
`aegis.core.secrets.KmsSecretsProvider` to fetch the key handle and sign via
the KMS client (`aegis.plugins.kms.CloudKmsClient`). The `SecretsProvider`
abstraction makes this a one-file swap.

## Verification

- `python -c "from aegis.core.asymmetric import Ed25519Signer, Ed25519Verifier; s=Ed25519Signer(); v=Ed25519Verifier(s.public_key); assert v.verify(b'x', s.sign(b'x'))"`
