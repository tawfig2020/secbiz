# Project Aegis — AI-Native Autonomous Defense for Regulated Industries

Reference implementation of spec v1.0 (Google AI Hackathon 2026).
**Stdlib-only**: Python 3.10+, zero dependencies.

Core thesis: prompt injection is unsolvable at the model layer (the OWASP
2026 number-one risk; NIST reports 81% agent-hijack success). Safety is
enforced **outside the model** — the MVP proves a fully compromised agent
cannot cause irreversible harm.

## Quickstart

```powershell
python demo.py                                    # end-to-end pillars demo
python demo_5min.py                               # 5-min narrative (spec §7.1)
python demo_bfsi.py                               # BFSI vertical prototype (AI Cup)
python demo_dashboard.py                          # command-center dashboard demo
python -m unittest discover -s tests -v           # test suite
```

## Module structure (spec §6.1)

```text
aegis/
├── semantic_gateway/      # Pillar 2 — inbound + outbound scanning
│   ├── detectors/         # 8 detectors: local_sequence_alignment, stylometric,
│   │                      # fatigue_tracker, deception_canary, mechanism_design,
│   │                      # spectral_signal, taint_tracker, multi_turn
│   ├── egress.py          # outbound scan: canary/prompt/secret/PII leaks
│   ├── latency.py         # LatencyBudget enforcement (fail_closed /
│   │                      # degrade_to_fast_path / alert_only)
│   ├── rate_limiter.py    # boundary guard: size cap + per-source/global limits
│   ├── classifier.py      # heuristic fusion + Gemini Flash adapter point
│   └── gateway.py         # fail-closed fusion; scan() in / scan_output() out
├── capability_bounded/    # Pillar 3 — provable containment
│   ├── reader_agent.py        # zero tool permissions
│   ├── reference_monitor.py   # evaluate() -> ALLOW/DENY/DEFER_HUMAN + tokens
│   ├── delegation.py          # strict attenuation: children never stronger
│   ├── approval_queue.py      # durable SQLite queue for DEFER_HUMAN
│   ├── executor_agent.py      # tool access, no NL path
│   └── capability_contract.py # spec §6.2 JSON schema (permitted/prohibited)
├── agentic_soc/           # Pillar 1 — Red/Blue loop on digital twin
│   ├── digital_twin.py, red_agent.py, blue_agent.py, harness.py
├── mtac/                  # Pillar 4 — polymorphic_env + key_manager (KMS)
├── qkd/                   # Pillar 5 — BB84 simulation, QBER abort
├── evaluation/            # adversarial_suite (500+ scenarios + multi-turn),
│                          # corpus_registry (disjoint TRAIN/VAL/TEST ledger),
│                          # adaptive_fuzzer (self-generating attacker),
│                          # baseline (status-quo comparison agent),
│                          # metrics_collector, regression_runner
├── self_improvement/      # HARD framework + failure_trace_analyzer
├── dashboard/             # command-center data plane: event_bus,
│                          # aggregator (3 views), text/JSON renderers
├── edge/                  # partner module: data-plane plug-in surface
│                          # (inspect_request/response/evaluate_action +
│                          #  stdlib HTTP adapter)
├── verticals/             # compliance packs: bfsi, healthcare, government
│                          # (sector detectors + contracts + egress rules
│                          #  + regulator control mappings)
├── plugins/               # tiered product line (Tier x Vertical = product):
│                          # tier, manifest, registry, orchestration,
│                          # metering, self-serve, business, enterprise,
│                          # marketplace
└── core/                  # hash-chained audit log + signed attestations
│                          #  + Merkle transparency log
```

## The containment guarantee

```text
untrusted doc -> ReaderAgent -> ReferenceMonitor -> ExecutorAgent
                (0 tools)      (contract + token)   (tools)
```

`action executes ⇒ action permitted by contract`. Prohibited actions are
denied outright; human-gated actions never auto-execute; executor accepts
only HMAC-signed single-use tokens — forged, expired, replayed, and
natural-language inputs all die at the boundary.

## P0 attack-surface coverage

- **Egress scanning** — `scan_output()` catches canary echo, system-prompt
  leaks, credential material (AKIA/JWT/sk-…) and bulk PII; sparse PII is
  redacted, not denied.
- **Multi-turn attacks** — `MultiTurnEscalationDetector` tracks per-source
  sessions: priming markers, instruction-density spikes, and soft strikes
  after grooming. `generate_multiturn_suite()` covers groom→prime→strike.
- **Adaptive fuzzer** — `AdaptiveFuzzer` evolves mutations (homoglyphs,
  clause shuffle, b64/ROT13 wrappers, synonym swap) guided by live bypass
  feedback; discoveries feed HARD's Observe phase automatically.
- **Boundary guard** — fail-closed payload size cap + sliding-window rate
  limits (per-source and global) before any detector runs.
- **Confusable folding** — `canonicalize` maps Cyrillic/Greek homoglyphs to
  ASCII so `ignоre` can't evade signature matching.

## Vertical packs (compliance-tiered packaging)

One core platform, industry modules — the packs configure a gateway
instead of forking it:

```python
from aegis.semantic_gateway import SemanticGateway
from aegis.verticals import load_pack

gw = SemanticGateway()
pack = load_pack("bfsi").configure_gateway(gw)   # adds sector detectors

contracts = pack.contract_registry()              # -> ReferenceMonitor
rows = pack.compliance_report()                   # DORA/HIPAA/FedRAMP map
```

| Pack | Sector detector | Contract anchors | Egress additions | Compliance map |
| --- | --- | --- | --- | --- |
| `bfsi` | SWIFT/payment manipulation + AML-bypass phrasing | wire transfers require human approval; `execute_swift_message` prohibited | IBAN | DORA, MiFID II, EU AI Act |
| `healthcare` | PHI exfiltration / chart mutation | `update_diagnosis` requires approval; `export_phi` prohibited | DOB, insurance ID | HIPAA 164.312, de-id, FDA PCCP |
| `government` | CUI extraction / declassification directives | `export_cui`, `access_above_clearance` prohibited | classification banners, portion markings | FedRAMP, NIST SP 800-53, FISMA |

Each pack also bundles sector threat-intel signatures (`threat_signatures`
+ `intel_feeds` names: FS-ISAC / H-ISAC / CISA) that auto-learn into the
sequence detector via `configure_gateway` — the same hook HARD uses.

## Tiered product line (aegis/plugins)

One core, many products. A product = **Tier (size) × Vertical (industry)**,
sold by toggling capability + limits — never by forking code:

```python
from aegis.plugins import Marketplace, StarterService, EnterpriseService

market = Marketplace()
print(market.catalog())                       # base products per tier
print(market.quote("enterprise", ("bfsi",)))  # base + add-on pricing

solo = market.subscribe("solo")               # -> ResolvedPlugin (generic)
service = StarterService(solo.plugin)         # self-serve API + metering
```

| Tier | Service | What it adds |
| --- | --- | --- |
| Solo / Startup | `StarterService` | self-serve HTTP API, usage metering, billing hook |
| SME / Business | `BusinessService` | dashboard, HARD self-improvement, vertical packs |
| Enterprise / Regulated | `EnterpriseService` | KMS signer, Merkle transparency log, live feeds, semantic judge |

Modules: `tier.py` (tier presets), `manifest.py` (`PluginManifest`),
`registry.py` (`PluginRegistry.resolve` — entitlement gate), `orchestration.py`
(`AgentRegistry` — `max_agents` enforcement), `metering.py`/`selfserve.py`
(B2C starter), `business.py`/`enterprise.py` (B2B tiers), `marketplace.py`
(catalog + add-on pricing + checkout).

Run `python demo_marketplace.py` for a walkthrough, or see `BLUEPRINT.md`
for the full roadmap.

## Configuration (placeholders)

All secrets and GCP resources are configured via placeholders, ready to be
swapped for real values without code changes:

- `config.example.json` — JSON config with `REPLACE_ME_*` placeholders.
- `.env.example` — environment variables (`AEGIS_*`) for Cloud Run.
- `aegis/config.py` — `Settings` + `load_settings()` (env vars override JSON).
- `bootstrap.py` — loads config and wires the full stack; prints which
  placeholders still need real values.

```python
from aegis.config import load_settings
settings = load_settings("config.json")
print(settings.placeholders())   # -> {'gcp_project_id': 'REPLACE_ME_...', ...}
```

Run `python bootstrap.py` for the current readiness report.

## Aegis Command Center (dashboard)

`aegis/dashboard` is a three-view governance layer over a single event
stream — attach an `EventBus` to the gateway and monitor and every
verdict becomes telemetry:

```python
bus = EventBus()
gw  = SemanticGateway(event_bus=bus)
mon = ReferenceMonitor(contracts, audit, event_bus=bus)

state = DashboardAggregator(bus, compliance_rows=pack.compliance_report()).snapshot()
print(render_all(state))          # exec + SOC + threat-intel views
payload = snapshot_dict(state)    # JSON-safe for a WebSocket front-end
```

- **Executive view** — Gartner-style cyber financial statement: balance
  sheet (assets, coverage, MTTC, compliance gaps) and income statement
  (attacks prevented vs. losses).
- **SOC analyst view** — live attack timeline, contract-decision feed,
  HARD self-improvement log.
- **Threat-intel view** — first/second-half trend deltas, forecast,
  self-improvement counters, active feeds.

`demo_dashboard.py` runs the 90s narrative: live attack -> contract
DENY/DEFER -> egress redaction -> HARD observes a real bypass, learns a
signature, and the re-scan blocks.

## The Aegis flavor (differentiation)

> Aegis is the only security platform where a fully compromised AI agent
> cannot cause irreversible harm — and the system proves it, improves
> itself, and shows you exactly how.

| Incumbent pattern | Aegis flavor |
| --- | --- |
| Google Agent Gateway: programmable data plane for partners | `aegis/edge` — capability-bounded containment as a plug-in; the only partner module returning *signed proof* per decision |
| Microsoft Copilot: AI assistant for analysts | Agentic SOC: autonomous Red/Blue closed loop — not an assistant, a self-improving defense system |
| CrowdStrike Falcon: endpoint + compliance modules | `aegis/verticals` — LLM-native semantic-layer packs with cross-domain detectors |
| Gartner financial-statement reporting | Command Center: financial statement + real-time SOC ops + self-improvement metrics in one stream |

### Signed containment attestations

Every Reference Monitor decision is minted as a signed `Attestation`
(`aegis/core/attestation.py`) binding contract, action, decision, params
digest, nonce, and timestamp — verifiable offline by a regulator or
customer without trusting the system's own claims.
`monitor.attestation_log` is append-only; the audit chain records every
signature.

Signing is pluggable: `HmacSigner` is the offline default; wrap a Cloud
KMS / HSM call in `CallableSigner` for production so the key never
leaves hardware and an insider cannot mint proofs.

## Explicit trust boundary

What attestations prove — and what they don't:

- **Proven** — every ALLOW/DENY/DEFER_HUMAN was computed against the
  stated contract, unmodified, by the monitor that held the key.
- **Not proven** — that the *input* was truthful; a signed denial of a
  spoofed request is still honest evidence the boundary held.
- **Attenuation** — `ReferenceMonitor.delegate(parent, child)` enforces
  strict attenuation: child actions ⊆ parent's, constraints only tighten
  (enums intersect, numeric bounds move inward, approval flags can only
  be added), prohibitions union, and depth is capped at 4. Each
  delegation mints a parent→child attestation, so provenance is preserved
  past the first hop — the confused-deputy hole is closed.
- **Held-out honesty** — the adversarial corpus is split by
  `CorpusRegistry` into disjoint TRAIN / VALIDATION / TEST sets.
  HARD evolves on TRAIN and is accepted/rejected on VALIDATION; consumed
  test cases are "burned" to TRAIN with a logged transition so headline
  metrics stay honest. `HardReport.generalization_gap` is the number
  customers should ask for.
- **Latency SLA** — packs declare `latency_budget_ms` + `latency_policy`
  and `configure_gateway` enforces it in `scan()`: `fail_closed` blocks
  (healthcare 200 ms), `degrade_to_fast_path` re-fuses on rules-only
  detectors (BFSI 500 ms), `alert_only` emits a `latency_budget` event
  (government 1000 ms).
- **DEFER_HUMAN has a consumer** — `ApprovalQueue` (SQLite, durable
  across restarts) captures every deferred action; `approve`/`deny`
  mints a resolution attestation and streams `approval_resolved`.

### Partner edge module

```python
from aegis.edge import AegisModule, serve_http
mod = AegisModule(gateway, monitor)          # plug into a data plane
mod.inspect_request(payload)               # -> ModuleVerdict + hits
mod.inspect_response(output)               # -> verdict + sanitized
mod.evaluate_action(action, contract_id)   # -> decision + attestation
serve_http(mod, port=8088)                 # stdlib HTTP: /inspect_request,
                                           # /inspect_response,
                                           # /evaluate_action, /healthz
```

## MVP success criteria (spec §5.1)

| Metric (spec §8.1) | Target | Where proven |
| --- | --- | --- |
| Detection latency p50 / p99 | <5ms / <20ms | `metrics_collector.py`, `regression_runner` gates |
| Gateway bypass rate | <5% | 500+ scenario suite, `run_regression` |
| Capability boundary bypass | 0% | `check_capability_boundary`; `test_capability_boundary_zero_bypass` |
| False-positive rate | <1% | regression gate `max_fp_rate` |
| Detection→containment | <500ms | `harness.py` `SOCResult.containment_ms` |
| Self-improvement | HARD loop | `self_improvement/hard_framework.py` |
| Provable containment proof | Signed attestations | `core/attestation.py`, `verify_attestation` |

## Build roadmap (Part 5)

| Phase | Deliverable | Status |
| --- | --- | --- |
| Core platform + spec | architecture, contracts, monitor | done |
| Semantic firewall | 8 detectors, fail-closed fusion | done |
| Dashboard v0.1 | `aegis/dashboard`, `demo_dashboard.py` | done |
| HARD v0.1 | six-phase self-improvement loop | done |
| BFSI pack | `aegis/verticals/bfsi.py` | done |
| Healthcare / Gov packs | `healthcare.py`, `government.py` | done |
| Partner edge module | `aegis/edge/partner_module.py` | done |
| Remediation: trust hardening | delegation attenuation, held-out HARD validation, latency-budget enforcement, approval queue, pluggable signers | done |
| Next | live FS-ISAC/H-ISAC/CISA feed connectors; FastAPI front-end over `snapshot_dict()`; KMS-backed signer + Merkle transparency log; semantic-classifier backend | queued |

## Baseline comparison (spec §7.1/§8.3)

`aegis/evaluation/baseline.py` models the status quo — LLM agent + keyword
guardrail, ambient-authority tool calls, no contracts. `demo_5min.py` Act 1
runs the identical buried injection through it and watches the exfiltration
succeed; Act 2 replays it through Aegis and shows the DENY. The contrast —
same fooled model, different boundary — is the product thesis.

## 5-minute demo

`demo_5min.py` follows the spec §7.1 script: hook → baseline breach (Act 1)
→ Aegis denial on a mock EHR (`export_patient_records` prohibited, Act 2) →
SOC loop + HARD evolution + live metrics dashboard (Act 3) → close.

## HARD framework

Each cycle: run the adversarial suite (Observe), cluster bypassed scenarios
and extract discriminating n-grams (Analyze), teach new signatures to the
local-sequence-alignment detector (Evolve), re-run regression and rollback
if security doesn't improve without hurting benign utility (Validate).

## Productionization notes

- `ReaderAgent(model_fn=...)` accepts any LLM callable; `GeminiClassifier`
  accepts a Vertex AI client (fail-closed fallback to heuristic fusion).
- `KMSKeyManager` is the Cloud KMS adapter point for MTAC epoch keys.
- `AuditLog` persists to WORM storage in deployment; BigQuery/Chronicle
  ingest maps to its `record()` interface.
- Pillar 5 models QKD statistics; bind to photonic hardware in deployment.
- Deployment target per spec §7.2: GKE + Istio mesh, Vertex AI for the
  Gemini judge; Prometheus histograms map to `MetricsCollector`, and
  OpenTelemetry containment traces map to the SOC harness timer.
