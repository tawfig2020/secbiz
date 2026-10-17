# Aegis — Honest Engineering Report

Date: 2026-10-12 · Status: **reference implementation, not production-ready**

This report replaces the earlier "35/35" accounting. It states what is
implemented and proven, what is documented but not implemented, and what is
open — with the evidence for each claim.

## Executive summary

Aegis has a working, fail-closed containment core and a credible engineering
scaffold around it. What is **not** yet true: multi-instance operation,
externally-validated detection numbers, real mTLS, real KMS/HSM, and a
declarative third-party vertical story. Those are the gaps between "impressive
prototype" and "credible system."

## 1. Implemented and proven

| Capability | Evidence |
| --- | --- |
| Semantic gateway (fail-closed fusion) | `python -m unittest discover -s tests -t .` — 246 tests pass, 0 skipped |
| Capability-bounded execution + strict attenuation | unit + property tests pass |
| Hash-chained audit log + RFC 9162 Merkle log | property test: single-byte mutation breaks chain |
| Ed25519 attestation (HMAC fallback) | property test: sign/verify round-trip |
| Money value object (Decimal minor units) | `tests/test_financial.py` |
| Idempotency-Key replay cache | `tests/test_financial.py` (durable SQLite) |
| Error taxonomy, observability, secrets, migrations | `tests/test_observability.py` |
| Concurrency correctness | `tests/test_concurrency.py` (token race, metrics race) |
| Fail-closed under partial failure | `tests/test_chaos.py` |
| Declarative vertical policy contract | `tests/test_vertical_policy.py` (BFSI policy + inline regex detector) |
| Shared durable store seams (Postgres/Redis) | `tests/test_stores.py` (fail-closed on missing driver) |
| Fuzzing | `python fuzz_gateway.py --iterations 2000` — 0 crashes |
| Packaging | `pip install -e .` builds an editable wheel; `python -m build --wheel` produces `dist/aegis-1.0.0-py3-none-any.whl` |

### Detection numbers (in-house, not external)

| Source | Bypass | False positive |
| --- | --- | --- |
| `python validate.py` regression suite | 3.1% | 0.0% |
| `python replay_heldout.py heldout.jsonl` (held-out split) | 3.0% (5/167) | 0.0% (0/94) |

These are **in-house synthetic corpora**. They are not a substitute for an
external red-team engagement (Risk I).

## 2. Documented but not implemented

| Item | Status |
| --- | --- |
| Postgres for nonces/usage/API keys (Risk B) | `PostgresStore` + `kv_store_from_env()` seam; not provisioned or load-tested |
| Redis rate limits (Risk B) | `RedisRateLimiter` + `rate_limiter_from_env()` wired into `server.py`; not provisioned or load-tested |
| mTLS / service mesh (Risk E) | documented; `server.py` has a server-TLS seam only |
| Alembic migrations | `alembic.ini` + `migrations/README.md`; working path is stdlib `run_migrations` |
| PQC (ML-KEM/Kyber) | seam only (`PqcKem`/`PqcKeyExchange`); no real backend |
| KMS/HSM secrets | `KmsSecretsProvider`/`VaultSecretsProvider` are stubs that refuse without a client |
| External red-team (Risk I) | not performed |
| Human-in-the-loop HARD approval | `docs/self-improvement-governance.md` defines it; code auto-accepts on gate pass |
| Terraform / Helm | scaffold in `docs/operations.md` only |
| Third-party vertical plugin contract | implemented (`load_vertical_policy`, `RegexDetector`, `bfsi.policy.json`); built-in packs still use code |
| Key rotation automation | policy in `docs/runbooks/key-rotation.md`; no automation |
| Audit archival to WORM | policy in `docs/runbooks/audit-retention.md`; no archival |

## 3. Known limitations

1. **Single-instance only.** Nonces, usage meters, API keys, and rate limits
   are in-memory in the reference build. `PostgresStore`/`RedisRateLimiter`
   seams exist but are not wired into those paths or provisioned, so the
   system still cannot run multi-instance (Risk B).
2. **SQLite durability.** The approval queue and audit log are single-node
   SQLite. No replication or failover.
3. **Detection numbers are unvalidated externally.** The 3.0–3.1% bypass rate
   is measured on in-house synthetic data. A hostile reviewer should treat it
   as unproven until an external red team replays `heldout.jsonl` (Risk I).
4. **HARD self-improvement has no human gate in code.** The governance doc
   requires human approval, but the loop currently auto-accepts on gate pass.
5. **KMS/Vault/PQC are stubs.** They raise `SecretUnavailableError` /
   `CryptoBackendUnavailableError` until a real client/backend is injected.
6. **Built-in verticals are still code.** `bfsi.py`, `healthcare.py`,
   `government.py` ship custom detector classes. The declarative path
   (`load_vertical_policy`, `RegexDetector`, `bfsi.policy.json`) is proven,
   but the built-in `*_pack()` functions do not consume it yet.
7. **QKD is a simulation.** `qkd/bb84.py` is educational and must not be
   presented as production key establishment.
8. **No real mTLS.** Transport security relies on the stdlib server's TLS
   seam; no mesh policy denies plaintext (Risk E).
9. **No key rotation automation.** Rotation is a manual runbook.
10. **No audit archival.** The chain is tamper-evident in-process but not
    anchored to WORM storage.
11. **Metrics are in-process.** Prometheus text exposition exists, but metrics
    are not shipped to a real sink.
12. **No load/scale testing.** Latency budgets are enforced per-scan, but no
    multi-instance or high-concurrency load test has been run.
13. **Stateful detector cross-contamination.** The fatigue tracker correlates
    by `source_id`; replaying a mixed corpus under one `source_id` inflates
    false positives. The honest per-payload measurement uses unique
    `source_id` per entry (`replay_heldout.py`).

## 4. Risk register with plan and dates

| Risk | Status | Plan | Target |
| --- | --- | --- | --- |
| B — shared durable stores | open | Postgres (nonces/usage/keys/queue/audit) + Redis (rate limits); swap `ReplayCache`/`RateLimiter` backends | before any pilot |
| I — external validation | open | engage red team; replay `heldout.jsonl`; publish results including failures | this month |
| E — mTLS / mesh | open | Istio/Linkerd `PeerAuthentication: STRICT`; deny plaintext | before production |
| C — Ed25519 default | closed | `default_signer()` returns Ed25519 when `cryptography` present | done |
| HARD human gate | open | wire `FeatureFlags.hard_loop` to an approval workflow | before BFSI pilot |

## 5. The honest statement

Here is what works, what is proven, what is not proven, and the plan to close
each gap:

- **Works:** fail-closed gateway, capability contracts, audit/Merkle integrity,
  Ed25519 attestation, Money, idempotency, error taxonomy, observability,
  concurrency and chaos tests, declarative vertical policies, durable-store
  seams, packaging, CI.
- **Proven (in-house):** 246 tests pass; 0 fuzz crashes; 3.0% bypass / 0.0% FP
  on the held-out split.
- **Not proven:** those detection numbers against a hostile external dataset;
  multi-instance correctness; real mTLS; real KMS/HSM/PQC.
- **Plan:** close Risk B (durable stores) and Risk I (external validation)
  first, then Risk E (mTLS) and the HARD human gate. Each has a target above.

A numeric "99% professional" score is not asserted. The artifacts above are
what a reviewer can verify today.
