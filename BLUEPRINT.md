# Aegis Product Blueprint — Core + Tiered Plugins (B2B + B2C)

Status: **Phase 0 + 1 scaffolded** (see `aegis/plugins/`). This document is the
living roadmap for turning the single core platform into a tiered product line.

## 1. The thesis

Security demand is not one market — it is a matrix of **enterprise size** and
**industry**. A solo startup cannot afford a Tier-1 bank's controls, and a bank
cannot run on a solo startup's footprint. The answer is **one strong core, many
products**, sold by toggling capability + limits — never by forking code.

Aegis already separates the two axes:

- **VerticalPack** (`aegis/verticals/`) = *what sector rules apply*
  (bfsi / healthcare / government).
- **Tier** (`aegis/plugins/tier.py`) = *how much of the core is enabled, at
  what footprint and price* (solo / business / enterprise / regulated).

A product = **Core + Tier (size) × Vertical (industry)**.

## 2. Architecture layers

```text
L1  Core (unchanged, universal)     5 pillars + attestation + audit
L2  Entitlement / Tier gate (NEW)   aegis/plugins — capability + limit profile
L3  VerticalPack (exists)           industry detectors/contracts/compliance
L4  AegisModule (exists)            data-plane plugin surface + HTTP
L5  Distribution (future)           self-serve API, billing, marketplace
```

The new layer is **L2**. `PluginRegistry.resolve(manifest)` wires the existing
`SemanticGateway` + `ReferenceMonitor` + `AegisModule` behind a `Tier`,
enforcing limits fail-closed:

```python
from aegis.plugins import PluginManifest, PluginRegistry, SOLO, ENTERPRISE

registry = PluginRegistry()
solo  = registry.resolve(PluginManifest(tier=SOLO))                 # generic starter
bank  = registry.resolve(PluginManifest(tier=ENTERPRISE, verticals=("bfsi",)))

solo.module.inspect_request("...")        # gateway scan
bank.module.evaluate_action("wire_transfer", "aegis.bfsi.transactions.v1", {...})
```

## 3. Tier definitions

| Tier | Target | Enabled | Footprint | Price band |
| --- | --- | --- | --- | --- |
| **Solo / Startup** | solo devs, indie hackers, early startups | rules-only gateway (no LLM judge), 1 agent, 3 contracts, HMAC attestation | single process, self-serve API | $29–99/mo or usage-based |
| **SME / Small Business** | 5–200 staff | + HARD self-improve, 1–2 vertical packs, dashboard, multi-agent | single tenant, managed | $500–2k/mo |
| **Blue Chip / Enterprise** | large enterprises | + agentic SOC, MTAC, QKD, all packs, custom contracts/detectors | dedicated VPC/GKE | $5k–50k/mo |
| **Regulated (Tier 1)** | banks, hospitals, gov | everything + KMS/HSM signer, Merkle log, fail-closed latency SLA | dedicated + compliance | $50k+/mo |

The tier flags live in `aegis/plugins/tier.py` (`Tier.capabilities()`).

## 4. Why "low cost, high volume" works

The core is stdlib-only with **zero marginal cost** for rules-only detection.
The only real variable cost is the LLM judge (`llm_judge`). The Solo tier ships
`llm_judge=False` → near-zero COGS → high margin at scale. That is the B2C moat.

The signed `Attestation` (`aegis/core/attestation.py`) is the premium
differentiator: the same proof exists at every tier, but only Regulated gets the
KMS/HSM + Merkle version an auditor or regulator will pay for.

## 5. Pricing / GTM model

- **B2C (Solo/Startup):** self-serve, credit card, flat or per-1k-scans.
  Land-and-expand — startups that grow upgrade to SME/Enterprise (B2B pipeline).
- **B2B (SME/Blue Chip/Regulated):** annual contracts, sales-assisted;
  compliance attestation is the premium wedge.

## 6. Roadmap

| Phase | Deliverable | Status |
| --- | --- | --- |
| 0. Formalize plugin contract | `Tier` + `PluginManifest` schema | **done** |
| 1. Entitlement gate | `PluginRegistry.resolve()` + tier tests | **done** |
| 2. Solo/Starter pack | self-serve HTTP API, usage metering, billing hook | **done** |
| 3. SME/Business pack | dashboard + HARD + 1–2 verticals, managed onboarding | **done** |
| 4. Enterprise/Regulated | KMS signer + Merkle log + live FS-ISAC/H-ISAC/CISA feeds + semantic classifier | **done** |
| 5. Marketplace | self-serve plugin distribution, per-vertical add-on pricing | **done** |

## 7. What shipped in this scaffold

- `aegis/plugins/tier.py` — `Tier` dataclass + `SOLO/BUSINESS/ENTERPRISE/REGULATED` presets.
- `aegis/plugins/manifest.py` — `PluginManifest` (tier + verticals + limits).
- `aegis/plugins/registry.py` — `PluginRegistry.resolve()` → `ResolvedPlugin`
  (gateway + monitor + module), `TierViolation`, `generic_contract()`. Now
  accepts `event_bus`, `classifier`, and `signer`; collects `compliance_rows`.
- `aegis/plugins/metering.py` — `UsageMeter` + `BillingHook` + `InMemoryBilling`
  (per-tenant scan/action counters forwarded to a pluggable billing sink).
- `aegis/plugins/selfserve.py` — `StarterService` + `serve_http` (signup /
  scan / evaluate_action / usage / healthz, API-key auth, fail-closed 401).
- `aegis/plugins/business.py` — `BusinessService` (dashboard snapshot, HARD
  self-improvement cycle, compliance report, `onboard()` provisioning).
- `aegis/core/merkle.py` — `MerkleLog` + `InclusionProof` (append-only
  transparency log with O(log n) inclusion proofs).
- `aegis/plugins/kms.py` — `KmsSigner` + `FakeKmsClient` (key never leaves
  hardware; refuses without a client).
- `aegis/plugins/feeds.py` — `FeedConnector` + `UrlFeed`/`StaticFeed` +
  `FEED_URLS` (FS-ISAC / H-ISAC / CISA signature ingestion).
- `aegis/plugins/enterprise.py` — `EnterpriseService` (KMS-signed
  attestations, Merkle root + proofs, live feed polling, semantic judge).
- `aegis/plugins/marketplace.py` — `Marketplace` + `Product` + `Subscription`
  (catalog, base-tier + per-vertical add-on pricing, self-serve checkout).
- `aegis/plugins/orchestration.py` — `AgentRegistry` + `AgentLimitExceeded`
  (enforces the tier's `max_agents` budget).
- `demo_marketplace.py` — end-to-end walkthrough (catalog → quote → subscribe
  → use Solo and Enterprise tiers).
- `benchmark.py` — internal validation benchmark (baseline vs Aegis + HARD +
  test suite) → `benchmark_report.json`.
- `poc_industry.py` — per-industry POC harness (bfsi/healthcare/government,
  synthetic data) → `poc_industry_report.json`.
- `validate.py` — CI/CD deploy gate (test suite + security regression).
- `aegis/config.py` — `Settings` + `load_settings()` (placeholder config,
  env-var override).
- `bootstrap.py` — loads config and wires the full stack; prints a readiness
  report of remaining placeholders.
- `config.example.json` / `.env.example` — placeholder config templates.
- `web/dashboard.html` + `web/dashboard.css` + `web/dashboard.js` — admin +
  end-user dashboard (white/black/blue/yellow, animated cards, analytics,
  industry catalog). Served at `/` by `server.py`.
- `docs/VALIDATION_PLAN.md` — phased validation procedure, standards
  alignment, copyright-safe POC dataset sourcing, GCP Cloud Run readiness.
- `tests/test_plugins.py` — 13 tests covering tier flags, generic-contract
  enforcement, vertical loading, fail-closed budget, truncation, and agents.
- `tests/test_selfserve.py` — 7 tests covering metering, billing hook,
  API-key auth, and the HTTP signup→scan→usage roundtrip.
- `tests/test_business.py` — 7 tests covering onboarding, dashboard flow,
  vertical contracts, compliance rows, HARD cycle, and tier gating.
- `tests/test_merkle.py` — 7 tests covering Merkle roots, inclusion proofs,
  tamper detection, and proof serialization.
- `tests/test_enterprise.py` — 8 tests covering KMS signer wiring, signed
  attestations, Merkle proofs, feed ingestion, and the semantic judge.
- `tests/test_marketplace.py` — 9 tests covering catalog listing, quoting,
  add-on pricing, checkout provisioning, and subscription summaries.
- `tests/test_orchestration.py` — 4 tests covering agent budget enforcement.
- `tests/test_config.py` — 5 tests covering config loading, env override,
  placeholder detection, and the KMS resource name.

Run: `python -m unittest discover -s tests`

## 8. Decisions resolved

1. **Contract budget semantics** — `resolve(truncate_verticals=True)` now
   auto-truncates verticals to fit the tier budget and records `warnings`;
   the default remains fail-closed (`TierViolation`).
2. **`max_agents` enforcement** — `AgentRegistry`
   (`aegis/plugins/orchestration.py`) enforces the tier's agent budget;
   `ResolvedPlugin.agents` is wired in `resolve()`.
3. **KMS signer wiring** — `CloudKmsClient` (`aegis/plugins/kms.py`) adapts a
   real Cloud KMS / HSM SDK client (sign/verify callables) into the
   `KmsClient` protocol; `KmsSigner` refuses without a client.

## 9. Remaining production work (not in this scaffold)

- Real Cloud KMS / HSM credentials + key-version provisioning (the adapter
  seam is ready; the SDK client is injected).
- Live FS-ISAC / H-ISAC / CISA feed endpoints (URLs are placeholders).
- Persistence for `AuditLog`, `MerkleLog`, `UsageMeter`, and API keys
  (currently in-memory).
- A real billing provider behind `BillingHook` (Stripe metered billing).
