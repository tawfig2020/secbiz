# AI Cup Hackathon — Submission Materials (BFSI)

Working title: **Aegis — Provable Containment for Agentic Payments (BFSI)**

## 5. Brief description (paste into the submission form)

> **Aegis** is an AI-native defense layer that makes a compromised banking
> agent harmless. Instead of trusting the model to refuse attacks, Aegis
> enforces safety outside the model: every inbound payload is screened by a
> fail-closed semantic gateway (8 detectors + a **Gemini** judge on the
> Generative Language API), and every action an agent proposes must satisfy a
> signed capability contract before a single-use, HMAC-verified execution
> token is minted. In the demo, an injected settlement instruction hijacks a
> baseline payments agent and sends a SWIFT message; the identical attack on
> Aegis is BLOCKED at the gateway, the wire transfer DEFERs to a human, and a
> forged token is refused — zero money moves.
>
> **Google Cloud usage:** the prototype is deployed on **Cloud Run**
> (`server.py`, stdlib container), uses **Cloud Firestore** as a durable
> evidence store (async sink writes tamper-evident audit events and verdicts
> to `aegis_events`), **Gemini 2.5 Flash** as the optional classifier judge
> that refines (never overrides) deterministic verdicts, and **Firebase
> Hosting** serves the command-center UI with `/api/**` proxied to Cloud Run.
> BFSI verticalization ships SWIFT-manipulation detection, four-eyes
> wire-transfer gating, IBAN egress scanning, and DORA / MiFID II / EU AI Act
> control mappings.

## 1. Pitch deck — slide outline (apply to the prescribed template)

| # | Slide | Content |
| --- | --- | --- |
| 1 | Title | Aegis — Provable Containment for Agentic Payments. Team, tagline: "The model will be fooled; the wire never leaves." |
| 2 | Problem | Prompt injection is OWASP #1; NIST reports 81% agent-hijack success. Agentic payment rails: injected instructions → unauthorized wires. |
| 3 | Insight | Model-layer defenses are advisory. Enforcement must live *outside* the model — same as banking already separates maker/checker. |
| 4 | Solution | 3-layer pipeline: Semantic Gateway → Reader (0 tools) → Reference Monitor → Executor (HMAC single-use tokens). Fully compromised agent cannot execute. |
| 5 | Demo stills | Screenshot: baseline exfiltrates vs. Aegis BLOCK/DENY/DEFER_HUMAN. `demo_bfsi.py` terminal or live dashboard. |
| 6 | GCP architecture | Diagram: Firebase Hosting → Cloud Run (gateway+monitor) → Firestore evidence; Gemini judge; Vertex AI path noted. |
| 7 | Metrics | 100% detection / 0% FP on BFSI corpus; sub-ms containment; 248-test suite; fail-closed latency budget 500 ms. |
| 8 | Compliance | DORA Art. 9–10/17, MiFID II 7-yr retention, EU AI Act Art. 15 — mapped controls, hash-chained audit log. |
| 9 | Business | Tiered product line (Solo→Regulated, $29→$50k+/mo); BFSI is the beachhead vertical (29% market share). |
| 10 | Ask/close | "Provable containment for agentic banking." Contact + repo link. |

## 2. Video demo — 3–4 min script

| Time | Scene | Voiceover |
| --- | --- | --- |
| 0:00–0:20 | Title + hook | "On Sep 8, 2026 an autonomous agent harvested thousands of credentials in six hours. The defense window is milliseconds." |
| 0:20–0:50 | Architecture slide | 3-layer diagram; enforcement outside the model. |
| 0:50–1:40 | **Baseline breach** | `python demo_bfsi.py` (or staged split-screen): injected MT103 settlement doc → baseline executes `execute_swift_message` → money gone. |
| 1:40–2:50 | **Aegis defense** | Same payload on the deployed prototype: gateway BLOCK 1.00 in ~2 ms; monitor DENYs `execute_swift_message`, DEFERs wire to human; forged token refused. Show Firestore console filling with evidence docs. |
| 2:50–3:30 | Proof + metrics | Batch corpus: 4/4 caught, 0 FP; SOC loop 100%→0%; compliance table; audit chain VALID. |
| 3:30–4:00 | Close | "Being fooled doesn't matter when containment is provable." Links: prototype URL + GitHub. |

Record the **live deployed link**, not localhost — judges cross-check item 3.

## 3. Deployed prototype link

- Cloud Run (live, verified): <https://aegis-575342873995.us-central1.run.app>
  — dashboard + `/api/scan` + `/api/evaluate` on one origin
- Firebase Hosting (live, verified): <https://secbiz.web.app>
  — `/api/**` rewrites to Cloud Run confirmed working end-to-end
- Firestore evidence: `secbiz / (default) / aegis_events` — writes
  confirmed live (docs appear within ~1 s of each scan)
- Verify `/healthz` + `/api/scan` before submitting; keep instance warm
  (Cloud Run min-instances=1 during judging if cold starts are a concern).

## 4. GitHub repository

- Repo: `github.com/tawfig2020/Codebase-Healing-Studio` (public)
- Push `main` before deadline; include this file, `docs/deploy-gcp.md`,
  `demo_bfsi.py`, `Dockerfile`, `firebase.json`.
