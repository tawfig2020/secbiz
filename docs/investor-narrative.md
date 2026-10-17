# Aegis — Why This Is Different (Investor & Partner Brief)

**Thesis:** every AI-security product on the market tries to make the
model *better behaved*. Aegis assumes the model is already compromised
and makes compromise *irrelevant*. That inversion is the innovation —
and it is implemented, tested, and deployed code, not a whitepaper.

---

## 1. The 2027–2030 threat no incumbent answers

| Emerging threat | What it does | Why today's tools fail |
| --- | --- | --- |
| **Agentic attack AI** | Autonomous agents that probe, adapt, and chain exploits at machine speed — no human operator, no business hours | Signature feeds and SOC playbooks assume human-speed attackers |
| **REA — "reverse-engineer anything"** | Frontier models decompile and model closed-source software, API schemas, and SaaS internals from behavior alone — secrecy of implementation stops being a defense | Security-by-obscurity collapses; anything an attacker can observe, an AI can model and exploit |
| **AI-assisted cryptanalysis** | Pressure on key management and token secrecy rises; long-lived secrets and static attack surfaces become liabilities | Static credentials and fixed internal topology give attackers infinite dwell time to break them |
| **Multi-agent decision chains** | Banks are wiring agent swarms into settlement, KYC, treasury. One hijacked agent propagates instructions to every peer that trusts it | Trust is ambient and transitive; nothing verifies *the action itself* |

The pattern under all four: **attackers now operate at machine speed
against surfaces that change daily, while defenders still operate at
human speed against surfaces assumed static.** Aegis was architected
for exactly this inversion.

---

## 2. Five mechanisms nobody else ships together

### 2.1 Capability-bound execution — containment, not alignment

The market's approach: better prompts, better models, more filters —
all *advice to the attacker-controlled component*. Aegis splits the
agent into an untrusted **Reader** (zero tool handles) and a
**Reference Monitor** that owns every tool behind signed capability
contracts. The Executor accepts only single-use, HMAC-verified,
expiring tokens — a fully hijacked agent can emit nothing but an
unauthorized *request*, and requests are denied, deferred, or
time-boxed by contract.

> **Analogy for non-technical partners:** we didn't give the teller a
> better lie detector. We took the teller's hands off the vault and
> put a bolted drawer between them. The teller can be replaced by a
> criminal — the drawer doesn't care.

*In code:* `ReaderAgent`/`ReferenceMonitor`/`ExecutorAgent`,
`CapabilityToken` (single-use, expiry, bound to action+params).

### 2.2 HARD — validated self-evolution, 24/7

`self_improvement/hard_framework.py` implements a continuous
DEPLOY → OBSERVE → ANALYZE → LEARN → EVOLVE → VALIDATE loop:

- Bypass attempts are clustered; recurring attack n-grams that don't
  appear in benign traffic are distilled into new detector signatures
  automatically.
- Contract hardening is *recommended* to humans, never auto-applied —
  the system evolves its detection but cannot quietly rewrite the bank's
  policy.
- Every evolution is validated against a **held-out attack set** with
  automatic rollback on regression — we measure the *generalization
  gap*: whether defenses catch attacks they've never seen. No
  competitor ships a "did our update generalize?" metric.

This is the answer to "how does it stay current?" — it doesn't wait
for a signature feed; it manufactures signatures from its own observed
failures, and refuses to ship ones that overfit.

### 2.3 Agentic SOC — adversarial co-evolution on a bank digital twin

`agentic_soc/` runs a Red Agent that learns which attack techniques
succeed (re-weighting toward what lands — adversarial adaptation, not
replay) against a **digital twin of a regulated estate**
(SWIFT gateway, core banking API, KYC ingestion, payment rails), while
a Blue Agent deploys countermeasures and the harness measures
detection-to-containment latency (sub-500 ms criterion).

The defense *pre-adapts*: by the time a novel attack reaches
production, Aegis has already played hundreds of rounds against
learning attackers in the twin. The SOC doesn't sleep; the twin
absorbs the risk so production doesn't.

### 2.4 MTAC — the anti-REA mechanism: polymorphic surface rotation

This is the direct answer to "reverse engineer anything." If an AI
can model your internals from observation, the counter is to make
observations *expire*. `mtac/polymorphic_env.py` remaps internal
resource names, routes, and schemas every epoch under a per-epoch key
(HMAC key hierarchy; Cloud KMS adapter point for production). A
stolen reconnaissance map is dead noise by the next epoch; an
intruder's memorized topology decays before the exploit is built.

> In market terms: moving-target defense has existed as research for a
> decade. Nobody productized it against *AI-speed reverse engineering*
> because the threat didn't exist at scale until now. The 2027+
> product category "defense against AI-driven reverse engineering" is
> one Aegis is already implementing.

### 2.5 Asymmetric AI trust — the Gemini judge can only tighten

`GeminiClassifier` fuses a learned model score with the deterministic
heuristic head as `max(heuristic, model_score)`, clamped, fail-closed
on error. An AI judge that can be fooled or DoS'd can **only make the
gateway stricter — never weaker**. The security property does not
depend on the AI being right; it degrades gracefully to deterministic
enforcement. Compare: guardrail products whose *entire* security
property is "the model was right."

### 2.6 The evidence spine — every decision is court-admissible

Every verdict mints a signed attestation (Ed25519; HMAC fallback) into
a hash-chained audit log, persisted to Firestore on Cloud Run. DORA
Art. 9–10/17, MiFID II 7-year retention, and EU AI Act Art. 15
mappings ship in the BFSI pack — compliance is a schema, not a
spreadsheet exercise after the fact.

---

## 3. Market comparison

| Category (examples) | What they do | Why they lose to agentic attackers |
| --- | --- | --- |
| Prompt-injection filters / AI guardrails (Lakera, Protect AI, Guardrails AI) | Classify inputs; advise the model | Advisory layer — the hijacked model ignores it; no control over tool use |
| Model-level alignment / safety training | Make the model refuse | The refusal mechanism is inside the component being attacked |
| Traditional WAF/API security | Pattern-match HTTP | Blind to semantic intent; nothing about agent tool calls |
| EDR/SOAR (human SOC) | Detect + respond | Human-speed loop vs. machine-speed attacker; after-the-fact |
| **Aegis** | Enforcement outside the model; tokens, contracts, self-evolving detection, rotating surface, signed evidence | The compromised component holds no capability; defense evolves and rotates at machine speed |

**Differentiation in one sentence:** incumbents sell better locks for
the front door; Aegis removes the keys from the person being
blackmailed and makes the building rearrange itself nightly.

---

## 4. Business cases for bank partners

1. **Settlement/desk agents (payments ops):** agent reads settlement
   instructions and proposes wires. *Without Aegis:* one poisoned
   MT103-adjacent document = unauthorized wire (the exact demo). *With
   Aegis:* injection BLOCKED; `execute_swift_message` DENIED by
   contract; `wire_transfer` DEFERRED to a human. **ROI:** one
   prevented fraudulent wire pays for years of licensing.
2. **Multi-agent treasury/KYC chains:** agents hand structured outputs
   to peer agents. Aegis contracts scope every hop — a compromised
   upstream agent cannot mint authority downstream. Lateral movement
   becomes structurally impossible rather than monitored-for.
3. **AI-native insider risk:** a rogue or manipulated internal agent
   exfiltrating customer data hits IBAN/PII egress scanning +
   prohibited-action contracts regardless of what the model "decided."
4. **Regulatory defense:** DORA testing + reporting duties and EU AI
   Act robustness obligations are met with machine-generated,
   signed evidence — cutting audit preparation from weeks to exports.
5. **Assurance for the REA era:** MTAC rotation bounds the value of
   any reverse-engineered map of the bank's agent estate to one epoch —
   turning "AI can learn our systems" from a catastrophic asymmetry
   into a recurring, expiring nuisance.

## 5. Honesty appendix (what partners will ask)

- **Implemented today:** the full containment pipeline, BFSI pack,
  gateway + Gemini judge, self-evolution with held-out validation and
  rollback, digital-twin SOC loop, MTAC rotation semantics, signed
  evidence spine, Cloud Run/Firebase deployment. 248 tests pass.
- **Pilot-readiness scope** (documented in `docs/bfsi-production.md`):
  KMS/HSM-backed keys instead of the local derivation path, Postgres
  for the evidence store, Redis rate limiting, mTLS partner channels,
  and independent red-team validation of the bypass metric.
- **Explicitly not claimed:** the QKD module is an educational
  simulation — the production path is ML-KEM; it is excluded from the
  BFSI pitch by design.

That honesty *is* the pitch to serious institutions: Aegis
distinguishes provable containment from simulation, which is exactly
the discipline the 2027–2030 threat landscape demands.
