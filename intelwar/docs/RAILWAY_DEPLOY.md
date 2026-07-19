# IntelWar Railway Deploy (PM-007)

**Classification:** Adjacent public shell — no constitutional trust claims by proximity.  
**Branch:** deploy from `intelwar` working tree (or a pushed `intelwar` branch).  
**Project:** Railway project `intelwar` (ARMORCLOUD workspace)  
**Project ID:** `e451ab4d-a7f7-4a20-9c76-d652774e548b`  
**Environment:** `production` (`c5d34eda-84a9-406c-9634-31ab83242dbe`)

## Live URLs (PM-007)

| Surface | URL |
|---------|-----|
| Web shell | https://intelwar-net-production.up.railway.app |
| Log API | https://log-api-production-0798.up.railway.app |
| Custom domain | `intelwar.net` — pending DNS + `railway domain intelwar.net --service intelwar-net` (requires authenticated CLI) |

Dashboard: https://railway.com/project/e451ab4d-a7f7-4a20-9c76-d652774e548b

## Services

| Service | Root | Public role |
|---------|------|-------------|
| `log-api` | `intelwar/services/log-api` | Living Log API + crosscheck verify + optional Kernel/DAG DB env gates |
| `intelwar-net` | `intelwar/apps/intelwar-net` | Public React shell (intelwar.net target) |

## Fail-closed rules (production)

1. **Web requires `VITE_LOG_API_URL`** at build time. Missing → build fails (no silent empty API).
2. **`INTELWAR_CORE_BIN` unset by default** in public deploy — appends remain `simulated: true` until Kernel binary + durable state are deliberately configured.
3. If `INTELWAR_CORE_BIN` / `INTELWAR_CROSSCHECK_BIN` / `INTELWAR_DAGDB_GATEWAY_URL` are set, incomplete config or bridge failure → **HTTP 503** (no simulated Permitted fallback).
4. Health/status endpoints must keep `trust_claim: "none"` and must not expose private keys or bootstrap tokens.
5. Rollback: undeploy or remove custom domain; unset `VITE_LOG_API_URL` and redeploy web to force fail-closed empty Log UX.

## Required variables

### `log-api`

| Variable | Required | Notes |
|----------|----------|-------|
| `PORT` | Railway provides | Listen port |
| `NODE_ENV` | `production` | |
| `INTELWAR_CORE_BIN` | optional | Leave unset for honest adjacent demo |
| `INTELWAR_CROSSCHECK_BIN` | optional | Leave unset unless core verify binary is shipped |
| `INTELWAR_DAGDB_*` | optional | All-or-nothing when URL set |

### `intelwar-net`

| Variable | Required | Notes |
|----------|----------|-------|
| `VITE_LOG_API_URL` | **yes** | Public HTTPS URL of `log-api` (no trailing slash) |
| `PORT` | Railway provides | Preview server |
| `RAILPACK_NODE_VERSION` | `20` | Pin Node |

## Deploy sequence

```bash
# 1) Create / link project (once)
railway init --name intelwar --workspace ARMORCLOUD
railway add --service log-api
railway add --service intelwar-net

# 2) Deploy API first
cd intelwar/services/log-api
railway up --service log-api --ci -m "intelwar log-api public"
railway domain --service log-api   # note https URL

# 3) Wire web to API, then deploy web
railway variable set VITE_LOG_API_URL="https://<log-api-domain>" --service intelwar-net
railway variable set RAILPACK_NODE_VERSION=20 --service intelwar-net
cd ../../apps/intelwar-net
railway up --service intelwar-net --ci -m "intelwar-net public shell"
railway domain --service intelwar-net

# 4) Optional custom domain (DNS must point at Railway)
railway domain add intelwar.net --service intelwar-net
```

## Validation after deploy

```bash
curl -fsS "https://<log-api>/health" | jq .
curl -fsS "https://<web>/" | head
# Browser: Living Log loads; consent demo appends simulated rows unless Kernel configured
```

## Secrets inventory

- No production signing keys shipped in this deploy by default.
- Demo consent remains Node-local fixture.
- Do not attach core bootstrap / emergency override credentials to these services.
