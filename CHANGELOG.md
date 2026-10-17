# Changelog

<!-- markdownlint-disable MD024 -- "Added/Changed/Fixed" repeat per release -->

All notable changes to Project Aegis are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/).

## [Unreleased]

### Added

- `demo_bfsi.py` — BFSI-focused prototype demo for the AI Cup Hackathon:
  injected settlement instruction vs. the BFSI vertical pack
  (SwiftManipulationDetector, `aegis.bfsi.transactions.v1` contract,
  IBAN egress, DORA/MiFID II/EU AI Act compliance map, bank-twin SOC loop).

## [1.0.0] - 2026-10-12

### Added

- Five-pillar containment architecture (semantic gateway, capability-bounded
  execution, agentic SOC, MTAC, QKD simulation).
- Hash-chained audit log + RFC 9162 Merkle transparency log.
- Signed attestations (HMAC + Ed25519 default).
- Strict capability delegation with attenuation.
- Durable human-approval queue (SQLite).
- Vertical packs (BFSI, healthcare, government) + compliance maps.
- Tiered product line + marketplace + metering.
- Dashboard (event bus, aggregator, views) + web UI.
- HARD self-improvement loop with held-out validation.

### Security & engineering hardening (expert-review round 2)

- `docs/threat-model.md` (STRIDE + LINDDUN).
- `aegis/core/errors.py` typed error taxonomy.
- `aegis/core/observability.py` (JSON logs, correlation IDs, Prometheus metrics).
- `aegis/core/secrets.py` (Env/KMS/Vault providers).
- `aegis/core/migrations.py` versioned migration runner.
- `aegis/core/money.py` Decimal money value object.
- `aegis/core/idempotency.py` idempotency-key replay cache.
- `aegis/core/features.py` feature flags.
- `aegis/core/asymmetric.py` PQC (ML-KEM/Kyber) seam.
- `aegis/verticals/loader.py` data-driven vertical loader.
- `pyproject.toml` (PEP 621 + ruff/mypy/pytest/import-linter/coverage).
- `src/` layout, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- `docs/concurrency.md`, `docs/openapi.yaml`, `docs/migrations.md`,
  `docs/self-improvement-governance.md`, `docs/adr/`, `docs/runbooks/`,
  `docs/operations.md`.
- `fuzz_gateway.py`, `sbom.py`, `requirements.lock`.
- Property tests, concurrency race tests, chaos tests, observability tests.
- Dockerfile + docker-compose, pre-commit config, benchmark gate.

### Changed

- QKD reframed as educational; production key establishment is PQC.

### Fixed

- Delegation flag-merge bug (bool is a subclass of int).
- Token replay race (atomic verify-and-burn).
- Approval-queue TOCTOU (conditional update).

## [0.1.0] - 2026-09-01

### Added

- Initial walking skeleton: gateway + reference monitor + signed attestation.
