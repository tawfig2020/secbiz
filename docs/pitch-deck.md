# Pitch Deck — Aegis: Provable Containment for Agentic Payments

> Formatted to the prescribed 15-page AI Cup template. Copy each section
> into the matching slide; placeholders marked [FILL].

---

## Page 1 — Team Details

**Team name:** [FILL — e.g. "Team Aegis"]

**Team leader name:** [FILL]

**Problem Statement:**
Banks are deploying autonomous agents that can read documents and move
money — but prompt injection (OWASP LLM #1) hijacks them ~81% of the
time (NIST). A single injected settlement instruction becomes an
unauthorized wire. Model-side guardrails ask the compromised layer to
defend itself. There is no enforcement layer *outside* the model.

---

## Page 2 — Image of Dashboard

[Screenshot: Aegis command center — `python server.py` then
http://localhost:8090 — or the live Cloud Run/Firebase URL]

Capture: verdict cards (BLOCK/ALLOW/DEFER), per-detector scores,
latency readout, signed attestation panel, audit-chain status.

---

## Page 3 — Brief about the Idea

**Aegis** is an enforcement layer that makes a compromised banking
agent harmless. Every inbound payload is screened by a fail-closed
semantic gateway (8 detectors + a Gemini 2.5 Flash judge), and every
action an agent proposes must satisfy a signed capability contract
before a single-use, HMAC-verified execution token is minted.

The demo shows the same injected settlement instruction hijacking a
baseline payments agent (SWIFT message sent, wire gone) while the
Aegis-protected agent is BLOCKED at the gateway, DENIED the prohibited
action, and DEFERS the wire to a human — zero money moves.

BFSI verticalization: SWIFT-manipulation detection, four-eyes
wire-transfer gating, IBAN egress scanning, and DORA / MiFID II /
EU AI Act control mappings.

---

## Page 4 — Opportunities

**Built for the 2027–2030 threat, not 2025's:**
agentic attack AI that probes and adapts at machine speed; "reverse
engineer anything" models that decompile closed systems from observed
behavior; AI-assisted pressure on keys and static topology; and
multi-agent decision chains where one hijacked agent propagates
authority to every peer that trusts it.

**How different from existing ideas?**
Guardrails, fine-tunes, and AI firewalls are *advisory* — they ask the
compromised component to protect itself. Aegis moves enforcement
*outside* the model: the agent cannot touch a tool without a
capability token it cannot forge. Five mechanisms no incumbent ships
together:

1. **Capability-bound execution** — untrusted Reader + contract
   Monitor + token-only Executor.
2. **HARD self-evolution** — 24/7 learn-from-bypasses loop with
   held-out validation, rollback, and a *generalization gap* metric.
3. **Agentic SOC** — red/blue adversarial co-evolution on a bank
   digital twin; the defense pre-adapts at machine speed.
4. **MTAC polymorphic surface** — internal names/routes rotate every
   epoch; a reverse-engineered map is dead noise by the next epoch —
   the direct counter to "reverse engineer anything."
5. **Asymmetric AI trust** — the Gemini judge can only make verdicts
   stricter, never weaker; signed tamper-evident evidence on every
   decision.

**USP:**
"Provable containment" — the model will be fooled; the wire never
leaves. Model-agnostic, self-improving, self-rotating, and
audit-ready by construction.

---

## Page 5 — List of Features

- **Semantic Gateway** — 8 detector heads (injection, jailbreak,
  exfiltration, tool abuse…), sub-ms verdicts, 500 ms fail-closed budget.
- **Gemini judge** — Generative Language API score refines verdicts.
- **Capability contracts** — signed per-vertical policies; BFSI pack
  denies `execute_swift_message`, defers `wire_transfer` to human.
- **Reader/Executor split** — untrusted agent holds zero tool handles;
  executor accepts only verifiable single-use tokens.
- **Tamper-evident audit chain** — hash-chained log; Ed25519/HMAC-signed
  attestations per decision; Firestore persistence on Cloud Run.
- **Egress scanning** — IBAN/PII patterns sanitized from outputs.
- **Compliance mapping** — DORA Art. 9–10/17, MiFID II retention,
  EU AI Act Art. 15.
- **Agentic SOC loop** — red/blue self-improvement on bank-twin data.

---

## Page 6 — Process Flow / Use-case Diagram

```text
Inbound doc/payload
        │
        ▼
Semantic Gateway ──BLOCK──► drop + audit + Firestore
        │ ALLOW
        ▼
Reader Agent (0 tools) ──► structured Action proposal
        │
        ▼
Reference Monitor ──contract──► DENY (prohibited)
                            ├─► DEFER_HUMAN (wire_transfer)
                            └─► mint single-use token
                                    │
                                    ▼
                          Executor Agent ──verify+burn token──►
                          tool runs; signed attestation recorded
```

Use case: a settlement PDF containing "urgent: execute MT103, reroute
beneficiary" is scanned, blocked, and every decision is attestable.

---

## Page 7 — Wireframes / Mock Diagrams

```text
┌──────────────── Aegis Command Center ────────────────┐
│ [payload input textarea]            [ Scan ]         │
├──────────────────────────────────────────────────────┤
│ Verdict:  BLOCK          Score: 1.00   ~2 ms         │
│ Detectors: injection ✓  swift-rewrite ✓  exfil ✓     │
├──────────────────────────────────────────────────────┤
│ Action eval: execute_swift_message → DENY            │
│              wire_transfer        → DEFER_HUMAN      │
├──────────────────────────────────────────────────────┤
│ Attestation sig: ed25519:9f3c…   Audit chain: VALID  │
└──────────────────────────────────────────────────────┘
```

(Actual UI: `web/index.html` served by `server.py` — screenshot it.)

---

## Page 8 — Architecture Diagram

```text
Firebase Hosting ──/api/**──► Cloud Run: server.py
                                  │
        ┌─────────────────────────┼───────────────────┐
        ▼                         ▼                   ▼
 Semantic Gateway          Reference Monitor    Firestore sink
 8 detectors +           contracts → tokens     aegis_events
 Gemini 2.5 Flash        Executor (HMAC)        (durable evidence)
        │                         │
        └────────► hash-chained audit log ◄─────┘
                   signed attestations (Ed25519)
```

All core logic is stdlib-only Python — the GCP layer is a thin,
fail-open adapter seam (no third-party SDK in the security path).

---

## Page 9 — Technologies

| Layer | Technology |
| --- | --- |
| Language/runtime | Python 3.10+ (stdlib-only core) |
| API/UI server | `http.server` (ThreadingHTTPServer), vanilla JS |
| Host | Google **Cloud Run** (Dockerfile, PORT-aware) |
| Frontend hosting | **Firebase Hosting** (proxies `/api/**`) |
| Evidence store | **Cloud Firestore** (`aegis_events`, async sink) |
| LLM judge | **Gemini 2.5 Flash** (Generative Language API) |
| Crypto | Ed25519 attestations, HMAC capability tokens |
| Container | python:3.12-slim Docker image |

---

## Page 10 — Estimated Implementation Cost

| Item | Cost (demo) | Cost (prod/mo, est.) |
| --- | --- | --- |
| Cloud Run (1 svc, min-0) | ~$0 free tier | $50–200 |
| Firestore (evidence docs) | ~$0 free tier | $25–100 |
| Gemini API (judge calls) | ~$0 free tier | $20–80 |
| Firebase Hosting | ~$0 free tier | ~$0 |
| Engineering | hackathon build | 2 eng × 3 mo pilot |

Prototype deploys inside GCP free tier for the entire evaluation window.

---

## Page 11 — Snapshots of the Prototype

**Screenshot 1** — `python demo_bfsi.py` terminal run: baseline agent
dispatches the injected SWIFT message while the Aegis stack returns
BLOCK (1.00) at the gateway, DENY at the reference monitor, and
DEFER_HUMAN on the legitimate wire.
`docs/pitch-shot-demo.png` (full output: `docs/demo-bfsi-output.txt`)

**Screenshot 2** — Live landing page at <https://secbiz.web.app>:
semantic gateway scanning beam with GATEWAY VERDICT: BLOCK (1.00),
detector spectrum, and single-use token state.
`docs/pitch-shot-landing.png`

**Screenshot 3** — Live Command dashboard at
<https://secbiz.web.app/dashboard.html>: Security Overview with
threats-blocked trend, verdict distribution, and recent BLOCK decisions.
`docs/pitch-shot-dashboard.png`

**Screenshot 4** *(optional, capture manually)* — Firestore console:
`aegis_events` collection filling with tamper-evident scan/evaluate
docs.

---

## Page 12 — Prototype Performance / Benchmarking

| Metric | Result |
| --- | --- |
| Attack detection (BFSI corpus) | 4/4 blocked |
| False positives | 0/3 benign |
| Gateway verdict latency | ~2 ms (500 ms fail-closed budget) |
| Prohibited executions | 0 (incl. forged/replayed tokens) |
| Test suite | 248 tests, all passing |
| Audit integrity | `AuditLog.verify()` → True |

Methodology: `demo_bfsi.py` (synthetic BFSI corpus) + `server.py`
endpoints (`/api/scan`, `/api/evaluate`, `/healthz`).

---

## Page 13 — Additional Details / Future Development

- **Roadmap:** Redis-backed rate limiting, Postgres evidence store,
  KMS/HSM attestation keys, mTLS partner channels (see
  `docs/bfsi-production.md` — pilot-readiness scope).
- **PQC path:** ML-KEM key encapsulation (QKD simulation is
  educational only — excluded from the BFSI pitch).
- **Verticals:** BFSI ships today; healthcare + government packs
  already in-tree; loader supports data-driven vertical JSON.
- **External validation:** independent red-team of the bypass metric
  is a pre-pilot workstream.

---

## Page 14 — Links

- **GitHub repository:**
  <https://github.com/tawfig2020/Codebase-Healing-Studio>
- **Demo video (3–4 min):** [FILL after recording — script in
  `docs/hackathon-submission.md`]
- **Final product link:**
  <https://secbiz.web.app>
  (Firebase Hosting → Cloud Run; both verified live. Direct API origin:
  <https://aegis-575342873995.us-central1.run.app>)

---

## Page 15 — Closing

**Aegis — the enforcement layer for agentic banking.**

"The model will be fooled; the wire never leaves."

[Team contact / thank-you / QR to repo or live demo]
