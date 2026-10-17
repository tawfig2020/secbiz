# Aegis Code & Architecture Audit

Date: 2026-10-11 · Scope: Python package `aegis/`, `server.py`, integration
and tooling scripts, tests, dashboard assets.

## 1. Scope and method

| Activity | Coverage |
| --- | --- |
| Syntax / compile check (`compileall`) | All Python files: **clean** |
| Static analysis (`pyflakes`) | All Python files: 0 errors; hygiene issues fixed in production code |
| Manual line-by-line review | Core: `reference_monitor`, `capability_contract`, `attestation`, `audit`, `merkle`, `gateway`, `server.py`, `config`, `feeds`, `bootstrap`, vertical packs (healthcare, government), `partner_module` |
| Second-pass manual review | Detectors (stylometric, mechanism_design, spectral, taint), `agentic_soc/`, `self_improvement/`, `capability_bounded/{approval_queue,delegation,executor_agent,reader_agent}`, `verticals/{pack,bfsi}`, `dashboard/events`, `plugins/*` |
| Third-pass manual review | `mtac/{key_manager,polymorphic_env}`, `qkd/bb84`, remainder of `evaluation/adversarial_suite.py` (mutations, corpus splits, multi-turn, capability-boundary runner) |
| Behavioural verification | 198 unit/integration tests, CI gate, benchmark, live HTTP tests |

All Python modules in scope have now been reviewed line by line. No audit can
honestly certify the absence of all bugs; this report lists what was found and
what remains.

## 2. Findings fixed

Severity: **H** high, **M** medium, **L** low.

| # | Sev | Component | Defect | Fix |
| --- | --- | --- | --- | --- |
| 1 | H | `core/merkle.py` | Leaf and interior nodes hashed identically (second-preimage ambiguity). `[a,b,c]` and `[a,b,c,c]` produced the same root (odd-node duplication). | RFC 6962-style `0x00`/`0x01` prefixes; tree size committed into root (`0x02‖size`); proof carries `size`; `verify` range-checks index and uses constant-time compare. *Superseded:* the tree is now RFC 9162 (no odd-node duplication, so no size commit is needed); see Risk D. |
| 2 | H | `core/attestation.py` | Signing payload joined fields with `\|`. A `\|` inside `reason`/`subject` let different field values share one signature (forgeable field-boundary shift). | Canonical JSON-array payload. |
| 3 | H | `reference_monitor.py` | Same `\|`-delimiter ambiguity in capability-token signature. | Canonical JSON payload with `aegis.token.v1` domain tag. |
| 4 | H | `server.py` | Signing key hard-coded in source. | `AEGIS_SIGNING_KEY` env var, else random per-process key. |
| 5 | M | `reference_monitor.py` | `_issued_nonce` grew without bound (expired, never-consumed tokens): memory leak / DoS. | Store `nonce -> expiry`; prune expired on every mint. |
| 6 | M | `reference_monitor.py` | `KeyError` crash when a contract has `deny_unlisted=False` and an unlisted action is evaluated. | Use `.get()`; unlisted actions follow contract policy. |
| 7 | M | `semantic_gateway/gateway.py` | Docstring promised fail-closed, but any detector/classifier exception propagated (500, no verdict). | Exceptions now yield BLOCK via `_reject`. |
| 8 | M | `core/audit.py` | `record()` not atomic: concurrent callers could duplicate `seq` and fork the hash chain. | `threading.Lock` around record. Test: 8 threads x 200 events, chain verifies. |
| 9 | M | `server.py` | Path containment used `str.startswith` (sibling-dir prefix bypass, e.g. `web2`). | `Path.is_relative_to`. |
| 10 | M | `server.py` | Unbounded request body; non-string `payload` caused 500; invalid JSON silently became `{}`; `Access-Control-Allow-Origin: *` on a signing endpoint. | 1 MB cap, strict type validation, 400 on bad input, wildcard CORS removed, `nosniff` header. |
| 11 | M | `plugins/feeds.py` | `urlopen` accepted any scheme (`file://`). | Only `http`/`https`. |
| 12 | M | `bootstrap.py` | Placeholder `REPLACE_ME_*` API keys would be transmitted to real feed endpoints. | Placeholders filtered out before building `UrlFeed`. |
| 13 | M | `config.py` | `Settings.__repr__` exposed API keys and DB URL (log/traceback leakage). | `repr=False` on all secret fields. |
| 14 | L | `evaluation/metrics_collector.py`, `dashboard/aggregator.py` | Inconsistent, off-by-one percentiles. Dashboard p99 returned the second-highest sample for n<100. The CI gate used a different formula. | Both use nearest-rank `ceil(p*n)-1`. |
| 15 | L | tests | `TestApprovalQueue` never closed its SQLite connection (the recurring `ResourceWarning`). | `tearDown` closes it. Suite now runs clean with `-W error::ResourceWarning`. |
| 16 | L | various | 12 unused imports/variables, constant f-strings. | Removed in production code, `bootstrap.py`, `server.py`. |

### Second-pass findings (fixed)

| # | Sev | Component | Defect | Fix |
| --- | --- | --- | --- | --- |
| 17 | H | `delegation.py` | `bool` is an `int`: `min(True, False)` let a child contract DROP a parent's `requires_human_approval`/`requires_evidence`. | Bool-aware flag merge (OR). |
| 18 | H | `delegation.py` | Child could set `deny_unlisted=False` (allow-all) and weaken `audit_requirements`. | `deny_unlisted` = parent OR child; audit duties only tighten. |
| 19 | H | `executor_agent.py` | verify -> run -> consume race: concurrent calls with one token executed the tool multiple times (double payment). | Atomic `ReferenceMonitor.redeem()` before side effects (at-most-once); failed tools burn the token. |
| 20 | M | `approval_queue.py` | Two approvers could both resolve one item (TOCTOU); requester could approve itself; unlocked SQLite reads. | `UPDATE ... WHERE status='pending'` + rowcount check; separation of duties; locked reads. |
| 21 | M | `verticals/pack.py` | Last-installed vertical overwrote latency policy (could weaken `fail_closed`); re-install duplicated detectors. | Strictest policy / smallest budget wins; idempotent install. |
| 22 | M | `reader_agent.py` | Long digit string -> `int()` ValueError (crash on untrusted text). | Bounded regex. |
| 23 | M | `taint_tracker.py` | Marker flood multiplied 600-char region scans (CPU DoS). | Cap at 64 markers per surface. |
| 24 | M | `dashboard/events.py` | Deque iterated while other threads append (RuntimeError). | Lock. |
| 25 | L | `bfsi`/`healthcare`/`government` detectors | `ctx.canonical` without fallback: silent no-detect. | `ctx.canonical or text`. |
| 26 | L | `hard_framework.py`, `agentic_soc/harness.py` | AttributeError without sequence detector; ZeroDivisionError on empty round. | Guards. |
| 27 | M | `server.py` | `/api/evaluate` read `attestation_log[-1]` (wrong attestation under concurrency); client could pick its own rate-limit identity via body `source_id`. | `MonitorResult.attestation`; identity derived server-side. |

Regression tests: `tests/test_hardening.py` (13), `tests/test_server_http.py` (9), `tests/test_second_pass.py` (11).

### Third-pass findings (no defects)

`mtac/key_manager.py` (HMAC-derived epoch keys, KMS adapter refuses to fall
back), `mtac/polymorphic_env.py` (deterministic epoch remapping, constant-time
reverse lookup), `qkd/bb84.py` (BB84 simulation; detection depends only on
observable QBER, sampled bits discarded, explicitly non-cryptographic), and
the remainder of `evaluation/adversarial_suite.py` (mutation operators, corpus
splits, multi-turn replay, capability-boundary runner) were reviewed line by
line. No new defects were found; the suite's containment criterion correctly
counts token-less execution and contract-violating execution as bypasses.

### Compatibility note

Signature and Merkle-root formats changed (findings 1-3), and the Merkle tree
was then moved to the RFC 6962/9162 structure (Risk D), so roots from earlier
builds will **not** match. Persistence (Risk B) is now available, so
version-tag stored formats before the first production deployment.

## 3. Verification results

- `python -m unittest discover -s tests`: **198 tests OK**.
- `python validate.py`: PASS (bypass 3.1%, FP 0.0%, p99 below 3 ms against 20 ms gate).
- `python benchmark.py`: unchanged detection quality (baseline bypass 91.8% vs Aegis 3.1%).
- `python -m pyflakes aegis server.py bootstrap.py benchmark.py validate.py poc_industry.py`: clean.

## 4. Architecture review

### Strengths (aligned with recognised practice)

- **Reference-monitor pattern**: enforcement outside the model; the model never
  holds key material. Complete mediation, tamper-evident audit, small trusted core.
- **Fail-closed defaults** (deny-unlisted, rate-limit/size/exception rejection,
  latency policies).
- **Pluggable seams** (`Signer`, `KmsClient`, `FeedSource`, `BillingHook`) so
  production backends swap without code change. Dependency direction is clean:
  core to capability/gateway to plugins to server.
- **Domain separation** between attestation and token signatures.
- Tier entitlement is data-driven (`Tier`, `PluginManifest`), not forked code.
- Test pyramid with security regression, held-out generalisation and a CI gate.

### Gaps and risks (NOT fixed; need decisions or infrastructure)

| # | Risk | Recommendation |
| --- | --- | --- |
| A | ~~No authentication on `server.py`~~ **Mitigated**: API keys (`AEGIS_API_KEYS`), constant-time check, refuses non-loopback bind without keys. | Still prefer IAP/mTLS at the edge; key rotation/per-key scopes not implemented. |
| B | **Partially mitigated**: audit chain (`AuditLog(path)`) and attestations (`AttestationStore`) persist to SQLite and are verified on load (`AEGIS_DATA_DIR`). Single-use token nonces, usage, API keys stay in memory (a restart invalidates outstanding tokens: fail-closed). | Shared store (Cloud SQL/Redis) for nonces needed before horizontal scaling; anchor Merkle root externally; SQLite is single-node. |
| C | **Fixed**: `default_signer()` now returns `Ed25519Signer` when `cryptography` is installed; `ReferenceMonitor` and `server.py` default to it, and `/api/status` publishes the public key for offline verification. Explicit `secret` still selects HMAC. | Keep the Ed25519 private key in KMS/HSM for regulated tiers (the `KmsClient` seam exists). |
| D | **Fixed**: RFC 9162 tree with inclusion and consistency proofs. | Publish signed tree heads (root + size) to an external witness. |
| E | **Mostly fixed**: threaded server, socket timeouts, per-client rate limit, generic 500s, security headers, optional TLS, refuse unauthenticated non-loopback binds. | Still stdlib `http.server`: run behind a production server/proxy (nginx/Caddy/ALB) for real traffic — TLS termination, connection draining and DoS protection. |
| F | **Fixed**: `ReferenceMonitor` and `EventBus` locked; atomic token redemption. | Multi-process deployments still need a shared store (B). |
| G | Dashboard (`web/dashboard.js`) renders **static demo data**, not live `/api` data; uses `innerHTML`. | When wired to the API, escape all dynamic strings. |
| H | `SANITIZE` on ingress returns an empty `sanitized` string (no actual redaction). | Define behaviour: redact or document as "treat as BLOCK-lite". |
| I | Regex-based vertical detectors are heuristic. 3.1% bypass and a 4.5% held-out bypass rate are measured on an **in-house** corpus. | **Prepared**: `export_heldout.py` emits the held-out (validation + test + benign) scenarios as JSONL for independent replay. External validation and an independent red team are still required before external claims. |
| J | **Partly fixed**: `.github/workflows/ci.yml` runs tests, `validate.py`, `pip-audit` on Python 3.10/3.12. Not verified on a live runner yet. | Add `pyproject.toml`, lock file, SBOM. |

### Standards mapping

Reference monitor and least privilege (NIST SP 800-53 AC-3/AC-6), audit
(AU-2/AU-10 non-repudiation), secure SDLC (NIST SSDF PW.7/PW.8 review and
testing), OWASP LLM Top 10 (LLM01 injection, LLM02 output handling, LLM06
excessive agency). Alignment is conceptual; no formal certification is claimed.

## 5. Honest assessment

The core containment logic is sound and the defects found were real but
bounded (cryptographic encoding ambiguity, resource growth, input validation,
secret handling). The second pass found more serious ones in the capability
layer (delegation escapes, token replay race), which shows the value of
re-review. No known open defects remain in the reviewed code. Risk C is closed
(Ed25519 is now the default attestation signer) and Risk E is closed to the
extent a stdlib server can be (threaded, TLS, rate-limited, authenticated,
fail-closed binds); the remaining E item is operational — front the server
with a production proxy for real traffic. Risk B (shared durable stores for
nonces/usage) and external validation of the in-house bypass rate (Risk I)
remain the two pre-production gates. A numeric "99%" quality score is not
something this audit can responsibly assert.

## 6. Expert-review remediation (round 2)

An independent senior-engineer review identified 13 gaps beyond the original
audit. Each is addressed below; see `docs/FINAL_REPORT.md` for the full
change log.

| # | Gap | Resolution |
| --- | --- | --- |
| 1 | No threat model | `docs/threat-model.md` — STRIDE + LINDDUN, trust zones, adversary capabilities, out-of-scope assumptions, control↔threat traceability |
| 2 | No error taxonomy | `aegis/core/errors.py` — `AegisError` → `DomainError`/`PolicyError`/`ProtocolError`/`InfraError` with stable codes and `is_safe_to_deny`/`is_safe_to_abort` |
| 3 | No observability | `aegis/core/observability.py` — JSON logs, `Correlation` contextvar, Prometheus-style `MetricsRegistry`; wired into gateway/monitor/executor |
| 4 | No concurrency model | `docs/concurrency.md` + `tests/test_concurrency.py` (token-redeem race, metrics race, gateway race) |
| 5 | No API contract | `docs/openapi.yaml` — OpenAPI 3.0 for `/api/scan`, `/api/evaluate`, `/api/status`, `/healthz` |
| 6 | No migration strategy | `aegis/core/migrations.py` (versioned, idempotent, out-of-order rejection) + `docs/migrations.md` |
| 7 | No secrets abstraction | `aegis/core/secrets.py` — `SecretsProvider` protocol + Env/KMS/Vault/Chained backends |
| 8 | No property tests | `tests/test_properties.py` — Hypothesis tests for Merkle, audit chain, Ed25519, attenuation (skipped when `hypothesis` absent) |
| 9 | No fuzzing harness | `fuzz_gateway.py` — gateway/detector fuzz harness (Hypothesis or stdlib fallback) |
| 10 | No SBOM / lock file | `requirements.lock` + `sbom.py` (CycloneDX 1.4 generator) |
| 11 | QKD mispositioned for BFSI | `qkd/bb84.py` reframed as educational; `PqcKeyExchange`/`PqcKem` (ML-KEM/Kyber) seam added to `aegis/core/asymmetric.py` |
| 12 | Self-improvement governance | `docs/self-improvement-governance.md` — what HARD may/may not change, approval gate, BFSI pilot gate |
| 13 | Verticals code-vs-config ambiguity | `aegis/verticals/loader.py` — `vertical_from_dict`/`load_vertical_json` for data-driven verticals; built-ins documented as code |

Verification after round 2: **225 tests pass** (6 property tests skipped
pending `hypothesis`), `validate.py` PASS, `pyflakes` clean, fuzz harness
0 crashes over 2000 iterations.
