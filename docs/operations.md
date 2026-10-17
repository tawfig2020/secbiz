# Operations & Production Maturity

This document records the Tier 4 operational items that require real
infrastructure and cannot be "implemented" inside a stdlib reference repo.
Each has a target state and a seam already present in the code.

## 1. IaC (Terraform)

Target: provision the GCP/Cloud Run deployment described in `README.md`.

```hcl
# infra/terraform/main.tf (scaffold)
resource "google_cloud_run_service" "aegis" {
  name     = "aegis"
  location = var.region
  template {
    spec {
      containers {
        image = "gcr.io/${var.project}/aegis:latest"
        env {
          name  = "AEGIS_ENVIRONMENT"
          value = "production"
        }
      }
    }
  }
}
```

Create `infra/terraform/` with `main.tf`, `variables.tf`, `outputs.tf`, and a
`backend.tf` (GCS state). Pulumi is an acceptable alternative.

## 2. Kubernetes manifests (Helm/Kustomize)

Target: `infra/k8s/` with a Deployment, Service, and NetworkPolicy. A Helm
chart (`infra/helm/aegis/`) is preferred for BFSI buyers.

## 3. mTLS via service mesh

Target: Istio/Linkerd sidecar with `PeerAuthentication: STRICT`. The code seam
is already present — `server.py` supports server-side TLS; the mesh terminates
mTLS in front of it. Do not rely on the stdlib server for transport security
in production (Risk E).

## 4. Shared durable stores

| Concern | Current | Target |
| --- | --- | --- |
| Nonces / usage / API keys | in-memory | Postgres |
| Rate limits | in-memory | Redis |
| Approval queue | SQLite | Postgres |
| Audit log | SQLite/in-memory | Postgres + WORM archival |

The `SecretsProvider` and `ReplayCache` abstractions already accept a durable
path; swap the backend without changing callers.

## 5. External red-team validation (Risk I)

`export_heldout.py` emits the held-out corpus as JSONL. Engage an independent
red team to replay it against the gateway and report the bypass rate. Until
this is done, the 3.1% in-house figure is not externally validated.

## 6. Key rotation & retention

See `docs/runbooks/key-rotation.md` and `docs/runbooks/audit-retention.md`.

## 7. Feature flags

`aegis/core/features.py` provides `FeatureFlags`; wire risky rollouts
(`hard_loop`, `pqc_key_exchange`) through it.

## 8. Chaos / failure injection

`tests/test_chaos.py` proves fail-closed under detector failure, oversized
payloads, unknown contracts, and unlisted actions. Extend with network/DB
fault injection in staging.

## 9. Self-improvement governance

`docs/self-improvement-governance.md` defines the approval workflow; enable
`hard_loop` only after human-in-the-loop approval and shadow mode.
