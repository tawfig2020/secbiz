# Internal Validation & Benchmarking Plan

Status: **localhost stage** — all wiring is built and runnable locally; cloud
deployment (GCP Cloud Run) is a later phase, not yet started.

This document defines the phased procedure for proving Aegis is safe and
credible to B2C and B2B customers. It is built on recognized international
standards and uses only **copyright-safe** test data (public domain, CC0,
MIT, Apache-2.0, or CC-BY with attribution).

---

## 1. Principles

1. **Localhost-first, cloud-ready.** Everything runs offline today. The
   benchmark and test suites have no external dependencies; cloud wiring
   (Cloud Run, KMS, live feeds) is stubbed behind seams.
2. **Copyright-safe by default.** We borrow *ideas and methods*, never
   verbatim text from proprietary standards. We only ingest test data whose
   license permits redistribution and derivative use.
3. **Standards-based, not standards-copied.** We align to NIST, OWASP, ISO,
   and SOC 2 outcomes, but we do not reproduce their copyrighted text.
4. **Fail-closed gates.** A single severe failure (e.g., one customer-data
   leak) fails the gate even if aggregate metrics look good.

---

## 2. Standards & frameworks we align to

| Framework | What we use it for | License / reuse note |
| --- | --- | --- |
| **NIST SSDF** (SP 800-218) | Secure software development lifecycle phases | US government work — public domain |
| **NIST AI RMF 1.0** | AI risk governance (Govern/Map/Measure/Manage) | US government work — public domain |
| **OWASP Top 10 for LLM Applications 2025** | Attack-category checklist (LLM01–LLM10) | CC-BY-SA 4.0 — attribute + share-alike |
| **OWASP LLMSVS v1.0** | LLM security verification levels 1–3 | CC-BY-SA 4.0 — attribute + share-alike |
| **OWASP Agentic Security Initiative (ASI)** | Agentic threat model + red-teaming | CC-BY-SA 4.0 — attribute + share-alike |
| **MITRE ATLAS** | Adversary technique taxonomy for AI | Free to use with attribution |
| **ISO/IEC 27001 / 42001** | ISMS + AI management system alignment | Copyrighted — purchase; we align conceptually only |
| **SOC 2 (AICPA TSC)** | Trust services criteria for B2B assurance | Copyrighted — align conceptually only |
| **Microsoft SDL / Google SRE** | SDL practices + SLI/SLO error budgets | Cite and paraphrase; do not copy |

> **Copyright rule:** NIST and CISA materials are US government works
> (public domain). OWASP materials are CC-BY-SA 4.0 — we may summarize and
> cite, but any derivative text must carry the same license. ISO and AICPA
> standards are proprietary; we reference their *concepts* only.

---

## 3. Phased internal validation procedure

### Phase 0 — Threat model & baseline

- Define the attack surface (prompt injection, indirect injection, excessive
  agency, exfiltration, output handling) using OWASP LLM Top 10 + MITRE ATLAS.
- Establish the **baseline**: an industry-status-quo agent (keyword guardrail
  plus ambient-authority tool calls, no capability contract).
- Deliverable: threat model + baseline harness (`aegis/evaluation/baseline.py`).

### Phase 1 — Unit & integration

- Run the full test suite (currently **179 tests**).
- Gate: 100% pass before any benchmark is trusted.
- Command: `python -m unittest discover -s tests`

### Phase 2 — Security regression (adversarial corpus)

- Run the 520-scenario adversarial corpus (OWASP/ATLAS-category templates
  with mutation operators) through the gateway.
- Measure detection rate, bypass rate, false-positive rate, latency.
- Gate (from `aegis/evaluation/regression_runner.py`):
  bypass > 5%, FP > 1%, p99 > 20ms → block.

### Phase 3 — Benchmark vs baseline

- Run the *same* corpus through the baseline and through Aegis.
- Prove the thesis: in-model guardrails are bypassable; out-of-model
  enforcement is not.
- Command: `python benchmark.py` (writes `benchmark_report.json`).

### Phase 4 — HARD self-improvement (held-out generalization)

- Run the HARD loop (deploy → observe → analyze → learn → evolve → validate).
- Only accept evolution if the held-out (unseen) set does not regress.
- Report the **generalization gap** — the number that tells a customer Aegis
  catches attacks it has never seen.

### Phase 5 — Industry POC (banking / fintech / healthcare / government)

- Load per-industry public datasets (Section 5) and run each vertical pack's
  detectors + contracts + egress rules against them.
- Deliverable: per-industry POC report with detection/FP numbers.

### Phase 6 — Red team & continuous validation

- Human red-teaming (OWASP ASI Red Teaming Guide) on top of automated evals.
- Wire the benchmark + test suite into CI/CD as a deploy gate.
- Re-run on every change; zero tolerance for severe failures.

---

## 4. Benchmark harness

`benchmark.py` produces a repeatable report with three sections:

1. **Test suite** — count + pass/fail.
2. **Containment** — baseline vs Aegis on the same corpus.
3. **HARD** — bypass before/after + held-out generalization gap + accepted.

Current local result (illustrative, regenerated on every run):

```text
baseline (keyword guardrail): bypass 91.8%, benign-blocked 0.0%
Aegis   (gateway + monitor) : bypass  3.1%, FP 0.0%, detection 96.9%
HARD generalization gap     : 1.5%
```

Metrics tracked: detection rate, bypass rate, false-positive rate, p50/p95/p99
latency, MTTC, attestation integrity, Merkle inclusion proofs.

---

## 5. Copyright-safe public POC data by industry

Only datasets with clear permissive licenses or public-domain status are used.
**Verify each license before committing the data to the repo** — do not
vendor data whose terms are ambiguous.

| Industry | Dataset | License / status | Use |
| --- | --- | --- | --- |
| Healthcare | **Synthea / SyntheticMass** (MITRE) | Apache-2.0 software; generated data "free from cost, privacy, and security restrictions" | Synthetic PHI/EHR for `healthcare` pack POC |
| Banking / fintech | **PaySim** (synthetic mobile-money fraud) | Verify on Kaggle (often CC0/other) | Fraud/transaction POC for `bfsi` pack |
| Banking / fintech | Synthetic SWIFT/MT103 message sets | Generate in-house (no third-party copyright) | Wire-transfer contract POC |
| Government / cyber | **CISA KEV** (Known Exploited Vulnerabilities) | US government — public domain | Threat-intel feed POC for `government` pack |
| Government / cyber | **MITRE ATT&CK** | Free with attribution | Technique mapping for red-team reports |
| Cross-industry | **Open-Prompt-Injection** (liu00222) | MIT License | Prompt-injection benchmark |
| Cross-industry | **PointGuardAI Prompt-Injection-OWASP-Benchmark** | Gated HF dataset — **verify license** | LLM01 injection benchmark |
| Cross-industry | **NIST datasets** | Public domain | General evaluation |

> **Rule:** prefer generating synthetic data in-house (no third-party
> copyright) over downloading ambiguous datasets. When downloading, record
> the source URL, license, and attribution in a `NOTICE` file.

---

## 6. GCP Cloud Run readiness (later phase — wiring only now)

The code is already structured for a clean lift to Cloud Run:

- **Stateless services** — `StarterService`, `BusinessService`,
  `EnterpriseService` are in-memory and container-friendly.
- **KMS seam** — `CloudKmsClient` (`aegis/plugins/kms.py`) adapts a real
  Cloud KMS/HSM client; swap `FakeKmsClient` at deploy time.
- **Live feeds** — `UrlFeed` (`aegis/plugins/feeds.py`) points at placeholder
  URLs; swap in real FS-ISAC / H-ISAC / CISA endpoints.
- **Persistence** — `AuditLog`, `MerkleLog`, `UsageMeter`, API keys are
  in-memory today; a Cloud Run deployment needs a durable store (Cloud SQL /
  Firestore) behind the same interfaces.

**Not yet done (deliberately):** container image, Cloud Run service config,
IAM/KMS key provisioning, secrets management, and live feed credentials.

---

## 7. What "done" looks like

- [x] Phases 0–4 are implemented and runnable locally (`benchmark.py`).
- [x] Phase 5: per-industry POC harness (`poc_industry.py`, synthetic data).
- [x] Phase 6: CI/CD deploy gate (`validate.py`); a recorded red-team
  engagement is still pending.
- [ ] Cloud: containerized Cloud Run deployment (later).
