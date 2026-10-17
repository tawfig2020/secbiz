# Aegis Agent Vault

A single-plugin prototype for the **Google AI Hackathon (BFSI track)**:
a capability-bounded banking agent that **provably cannot** execute
unauthorized actions.

> A compromised banking agent cannot cause irreversible harm — and it proves it.

## What it does

One untrusted message flows through four independent layers:

```text
untrusted text -> SemanticGateway -> ReaderAgent -> ReferenceMonitor
               -> ExecutorAgent -> egress scan
```

- **SemanticGateway** blocks prompt-injection payloads inbound.
- **ReaderAgent** (the "fooled model") emits a structured action intent.
- **ReferenceMonitor** enforces a capability contract *outside the model*:
  prohibited actions are `DENY`, human-gated actions are `DEFER_HUMAN`,
  permitted actions mint a single-use capability token.
- **ExecutorAgent** accepts only valid, unredeemed tokens — no natural
  language, no forged/replayed tokens.
- **Egress scan** redacts leaked PII/credentials before output leaves.
- Every decision is a **signed attestation**, verifiable offline by a
  regulator without trusting the system.

## Run

```powershell
python -m agent_vault.demo          # 60-second narrative demo
python -m agent_vault.smoke_test    # assertions (no pytest needed)
python -m agent_vault.server        # HTTP API on :8080
```

## HTTP API

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| POST | `/process` | `{"text": "...", "source_id": "customer"}` | full containment pipeline |
| POST | `/evaluate_action` | `{"action": "wire_transfer", "params": {...}}` | mediate one action |
| POST | `/inspect_response` | `{"output": "..."}` | egress PII/secret scan |
| GET | `/attestations` | — | signed decision log |
| GET | `/healthz` | — | liveness probe |

## Optional: Gemini-on-Vertex-AI semantic judge

By default the gateway uses the deterministic heuristic fusion head. To add
an advisory Gemini judge (refines the score, never overrides a confident
heuristic block), install the Vertex AI SDK and set the project:

```powershell
pip install google-cloud-aiplatform
$env:AEGIS_GEMINI_PROJECT = "my-gcp-project"
$env:AEGIS_GEMINI_LOCATION = "us-central1"
$env:AEGIS_GEMINI_MODEL   = "gemini-2.5-flash"
```

`AgentVault` auto-detects these env vars (or accepts an explicit
`gemini_client=`). If the SDK is missing or the call fails, it silently
falls back to the heuristic head — safety never depends on model availability.

In Docker, include the SDK with the opt-in build arg (the default image is
lean/stdlib-only):

```powershell
docker build --build-arg INSTALL_VERTEX=true -f agent_vault/Dockerfile .
```

## Docker build test

```powershell
powershell -File agent_vault/test_docker.ps1
```

Builds the image and runs the smoke test inside the container, then starts
the server and checks `/healthz`.

## Deploy (Cloud Run)

```powershell
gcloud run deploy agent-vault `
  --source . `
  --region us-central1 `
  --allow-unauthenticated `
  --port 8080
```

The image is stdlib-only (`python:3.12-slim`); no GPU, no external services.
Optional: `pip install cryptography` upgrades attestations to Ed25519
(asymmetric — auditors hold only the public key and cannot forge proofs).

## Contract

`agent_vault/contract.py` declares the boundary. `wire_transfer` requires
human approval; `execute_transfer`, `modify_swift_message`, and
`export_customer_pii` are prohibited. A hijacked agent cannot edit it —
the monitor enforces it outside the model.
