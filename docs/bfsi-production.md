# BFSI Vertical — Production Shape & Pain Points

This is the end-to-end hardening plan for the BFSI vertical, and the
roadmap template for the other verticals (healthcare, government).

## What is wired now

| Concern | Reference build | Production switch |
| --- | --- | --- |
| Rate limits | in-memory `RateLimiter` | `AEGIS_REDIS_URL` → `RedisRateLimiter` (`aegis/core/backends.py`) |
| Nonces / usage / API keys | in-memory / SQLite | `AEGIS_POSTGRES_DSN` → `PostgresStore` (`aegis/core/stores.py`) |
| Secrets | env | `KmsSecretsProvider` / `VaultSecretsProvider` (`aegis/core/secrets.py`) |
| Attestation | Ed25519 (HMAC fallback) | KMS/HSM signer via `SecretsProvider` |
| Transport | stdlib TLS seam | Istio/Linkerd `PeerAuthentication: STRICT` |

The gateway command center (`server.py`) already selects the rate-limiter
backend from the environment; the KV store factory is available for the
nonce/usage/API-key paths.

## Provisioning steps (BFSI)

1. **Postgres** — provision a managed Postgres (Cloud SQL / RDS); set
   `AEGIS_POSTGRES_DSN`. Run `aegis/core/migrations.py` (or Alembic) to create
   `aegis_kv`, `approvals`, `audit_log`.
2. **Redis** — provision a managed Redis; set `AEGIS_REDIS_URL`. The gateway
   now uses `RedisRateLimiter` automatically.
3. **Secrets** — create the KMS key (or Vault path); inject a real client into
   `KmsSecretsProvider`/`VaultSecretsProvider` (currently they refuse without
   one).
4. **mTLS** — deploy Istio/Linkerd; set `PeerAuthentication: STRICT` and a
   `DestinationRule` requiring mTLS. The stdlib server sits behind the mesh.
5. **Logs** — ship `JsonFormatter` output to the sink (Cloud Logging /
   Datadog / Loki); correlation IDs are already on every event.
6. **Metrics** — scrape the Prometheus text endpoint into Prometheus/Grafana.

## Pain points (and what they mean for other verticals)

1. **Stateful detectors need per-source isolation.** The fatigue tracker
   correlates by `source_id`; a shared `source_id` across tenants inflates
   false positives. Every vertical must pass a unique tenant-scoped
   `source_id` (the self-serve layer already does `t_<key_hash>`).
2. **In-memory state is the blocker, not the detectors.** Nonces, usage, and
   API keys are the first things to move to Postgres/Redis. The detector code
   is already stateless enough to scale; the stores are not.
3. **Secrets are stubs until a real KMS/HSM is injected.** The abstraction is
   correct, but "works with env" is not "works with HSM." Budget for the KMS
   integration before claiming production readiness.
4. **mTLS is a mesh concern, not an app concern.** The stdlib server's TLS
   seam is not enough; the mesh must deny plaintext. This is identical for all
   verticals — do it once at the platform layer.
5. **QKD must not appear in BFSI conversations.** It is an educational
   simulation; the practical PQC path is ML-KEM/Kyber (`PqcKem`). Keep QKD out
   of the BFSI pitch.
6. **The 3.0% bypass number is in-house.** Until an external red team replays
   `heldout.jsonl`, do not present it as validated. This is the gate for BFSI.

## Checklist before BFSI pilot

- [ ] Postgres provisioned + migrations applied.
- [ ] Redis provisioned + rate limiter switched.
- [ ] KMS/HSM signer injected (no env fallback in production).
- [ ] mTLS `STRICT` enforced; plaintext denied.
- [ ] Logs shipped to a real sink; correlation IDs verified end-to-end.
- [ ] External red-team replay of `heldout.jsonl` published.
- [ ] HARD human-in-the-loop approval enabled (`FeatureFlags.hard_loop`).
