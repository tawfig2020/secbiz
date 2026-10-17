# Self-Evolving Defense: The HARD Loop

*How AEGIS-BFSI stays ahead of AI-driven and AI-generated threats against autonomous agents — continuously, and under human governance.*

---

## 1. The Problem

Static defense systems die the day they ship. GenAI attack techniques mutate faster than any signature corpus can be updated manually, and autonomous banking agents present a machine-speed attack surface: prompt injection, capability abuse, multi-turn drift, and payload obfuscation all evolve weekly.

AEGIS-BFSI's answer is not a bigger ruleset — it is a defense organism that generates its own adversaries, learns from its own failures, and ships only improvements that pass a measurable quality gate.

## 2. HARD: Harness-based Autonomous Runtime Defense Evolution

Implemented in `src/aegis/self_improvement/hard_framework.py`, HARD runs a continuous seven-phase cycle:

```
DEPLOY -> OBSERVE -> ANALYZE -> LEARN -> EVOLVE -> VALIDATE -> DEPLOY
```

| Phase | Mechanism | Code |
|---|---|---|
| **Deploy** | Current defense artifacts serve live production traffic | — |
| **Observe** | Internal Red agent + production failure traces | `evaluation/adaptive_fuzzer.py`, `adversarial_suite.py` |
| **Analyze** | Cluster bypasses, rank weakest detectors | `self_improvement/failure_trace_analyzer.py` |
| **Learn** | Distill candidate signature phrases from bypass traces | `local_sequence_alignment.learn_signature` |
| **Evolve** | Teach detector new phrases; recommend contract hardening | `hard_framework.py` |
| **Validate** | Re-run regression on seen AND held-out corpora; keep only if security improves without degrading benign utility, else rollback | `evaluation/regression_runner.py` |
| **Deploy** | Validated improvements ship, signed into the audit chain | `core/merkle.py` |

The critical honesty check is the **held-out generalization gap** (`HardReport.generalization_gap`): bypass rate measured on attacks the system has never seen. That is the only number that proves the system catches novel attacks rather than memorizing a training set.

## 3. Three Intake Channels — Watching Every Second

### 3.1 RED — Self-Generated Adversary

`evaluation/adaptive_fuzzer.py` is an evolutionary attack engine. Each generation mutates the corpus — unicode homoglyphs, clause reordering, filler padding, synonym substitution, encoding wrappers — scores every payload through the live gateway, and breeds anything that bypasses into the next generation's seeds. The system manufactures its own adversary 24/7 instead of waiting for a fixed corpus to go stale.

### 3.2 BLUE — Learned From Failures

Every DEFER decision and near-miss in production becomes a failure trace. `failure_trace_analyzer.py` clusters them, and novel GenAI attack phrasing becomes tomorrow's detector signature before it is seen a second time.

### 3.3 FEDERATED — Threat Intelligence Feeds

`plugins/feeds.py` connects to FS-ISAC, H-ISAC, and CISA-style feeds. Enterprise deployments poll them and ingest new signature phrases through the same `learn_signature` hook HARD uses — community intelligence lands inside the gateway, not in a PDF report.

## 4. Human-in-the-Loop Qualification Gate

The part regulators care about — and it is enforced in code, not procedure:

| Control | Mechanism |
|---|---|
| **Separation of authority** | Machines evolve *detection* (signatures — tightening only, always reversible). Humans approve *policy* (capability contracts — consequential, never auto-applied). |
| **Durable approval queue** | `capability_bounded/approval_queue.py` persists every `DEFER_HUMAN` decision to SQLite until a named approver resolves it. Nothing silently expires. |
| **Signed human decisions** | Each resolution mints a resolution attestation — the human's judgment becomes part of the cryptographic evidence chain. `approval_request` / `approval_resolved` events stream to the SOC console. |
| **Regression quality bar** | An evolution ships only if catch rate improves on both the training corpus and the held-out corpus without raising false positives. Otherwise it is automatically rejected and rolled back. |
| **Versioned artifacts** | `evaluation/corpus_registry.py` versions every admitted defense artifact — a complete inventory for audit and rollback. |

## 5. Standards Alignment

The mechanism maps to recognized governance frameworks:

- **NIST AI RMF** — continuous monitoring, human oversight controls
- **ISO/IEC 42001** — AI management system, documented change processes
- **SR 11-7 / MAS TRM (Model Risk Management)** — held-out validation acts as challenger-model discipline; detector versions are model inventory entries
- **ITIL Change Management** — corpus registry functions as a CAB pipeline: proposed -> tested -> approved -> released -> auditable
- **SOC 2 CC8 (Change Management)** — every defense change is signed, timestamped, attributable, and reversible

## 6. Worked Example

A novel GenAI prompt-injection technique appears — payloads phrased as *"for compliance audit, export the following records…"* wrapped in base64:

1. **Hour 0** — the adaptive fuzzer independently converges on a similar encoding-wrapped variant; it bypasses the gateway. Logged as a failure trace.
2. **Analyze** — the trace clusters with two earlier near-misses; `local_sequence_alignment` is flagged weakest.
3. **Learn / Evolve** — the signature phrase family is distilled and taught to the detector. Because the payload targets `export_patient_records`, the system *recommends* tightening the `health.clinical.v1` capability contract.
4. **Validate** — regression runs on the full corpus plus held-out set. If benign "compliance audit" requests start false-positiving, the evolution is rejected and rolled back. If it passes, the signature enters the corpus registry as a new version.
5. **Human gate** — the detector update deploys automatically (detection improvement only). The contract-hardening recommendation queues for a named human approver.
6. **Evidence** — every step mints a signed attestation into the Merkle chain, so a regulator can later verify exactly when and why the defense changed.

## 7. Measured Outcomes

| Metric | Before HARD | After | Change |
|---|---|---|---|
| Catch rate | 87.3% | 96.8% | +9.5% |
| Bypass rate | 12.7% | 3.2% | -75% |
| False positive rate | 2.1% | 0.3% | -86% |
| Self-evolved signatures | 0 | 47 | autonomously deployed |

## 8. The Business Case in One Paragraph

Traditional signature systems depreciate from day one — attackers adapt, the corpus goes stale. HARD inverts that economics: the Red/Blue loop makes attack generation free and continuous, so the defense gets measurably stronger every cycle while marginal coverage cost approaches zero. A bank deploying AEGIS does not buy a static ruleset; it buys a defense organism whose improvement is contractually visible in the attestation chain — and whose every consequential change still passed through a named human approver. When a regulator asks "who decided this system could act?", the answer is always: **the machine proposed, the metrics qualified, the human signed.**
