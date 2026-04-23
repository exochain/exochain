# exoguard on Railway — pilot runbook

This directory ships the deploy config for **exoguard**, the constitutionally-adjudicated DLP gateway for corporate LLM workflows. It runs as a separate Railway service alongside the exochain node zero (`n0`).

## Architecture

Three Railway services under one project, one managed Postgres plugin:

| Service | Source | Purpose |
|---|---|---|
| `exochain-n0` | repo-root `Dockerfile` + `railway.json` | Constitutional node zero — genesis + DAG |
| `exoguard` | `infra/railway/Dockerfile.exoguard` + `infra/railway/railway.json` | DLP facade + MCP transport |
| `exo-scanner` | (follow-up) | Ollama sidecar for local PHI/PII scanning |

TLS terminates at Railway's managed domain. Service-to-service auth uses exoguard identity signatures — not shared secrets.

## First-deploy checklist

1. **Create the Railway project** and attach a Postgres plugin.
2. **Deploy `exochain-n0`** first so its DAG exists.
3. **Genesis n0**: `railway run -s exochain-n0 exochain n0-genesis --write-receipt` → commit the resulting `n0-genesis.receipt.json` back to this directory on the pilot branch.
4. **Deploy `exoguard`** with these env vars (no plaintext secrets beyond these two):
   - `EXOGUARD_IDENTITY_REF=did:exo:service/exoguard-pilot`
   - `EXOGUARD_N0_DAG_URL=${{Postgres.DATABASE_URL}}` *(Railway reference)*
5. The facade refuses to start if `verify_chain()` on the n0 `McpAuditLog` fails.

## Secrets model

All runtime secrets (OpenRouter API key, tenant webhook URLs, custodian references, tenant policies) are fetched via **signed MCP calls** from the DAG at request time — never injected as plaintext Railway env vars. The only secrets Railway holds are:

- `DATABASE_URL` (managed Postgres, auto-rotated)
- `EXOGUARD_IDENTITY_REF` (public DID — not a secret, just a pointer)

Everything else lives encrypted in the DAG under the `KeyCustodian` (MVP: `SingleKeyCustodian`; frozen-interface stub for 3-of-4 multisig).

## Deploys are receipts

CI (`.github/workflows/railway-deploy.yml`) posts a `mcp_exoguard_ops.deployExoguard` MCP call **before** triggering `railway up`. The resulting `McpAuditRecord` ID is the deploy receipt — stored in the Railway deployment environment and queryable via `dlpAuditRecord(id)` on the GraphQL surface. A deploy that kills mid-flight leaves the audit record in `outcome=Blocked` rather than orphaned.

## Rollback

```
# Rollback is itself a signed + quorumed MCP call.
railway redeploy <previous-deployment-id>
```

The previous deployment ID is recorded in the original `deployExoguard` audit record, so every rollback is also an auditable event.

## Smoke

See `crates/exo-dlp/PILOT_SMOKE.md` for the full post-deploy check list.
