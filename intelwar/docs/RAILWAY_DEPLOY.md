# IntelWar Railway Deploy (PM-007)

**Classification:** Adjacent public shell — no constitutional trust claims by proximity.  
**Branch:** deploy from `intelwar` working tree (or a pushed `intelwar` branch).  
**Project:** Railway project `intelwar` (ARMORCLOUD workspace)  
**Project ID:** `e451ab4d-a7f7-4a20-9c76-d652774e548b`  
**Environment:** `production` (`c5d34eda-84a9-406c-9634-31ab83242dbe`)

## Live URLs (PM-007)

| Surface | URL | Host locks to |
|---------|-----|----------------|
| **Home** | https://intelwar.org · https://www.intelwar.org | `.org` |
| **Spine** | https://intelwar.press · https://www.intelwar.press | `.press` |
| Living Log | https://intelwar.net · https://www.intelwar.net | `.net` |
| CrossCheck | https://intelwar.ai · https://www.intelwar.ai | `.ai` |
| Provenance | https://intelwar.tv · https://www.intelwar.tv | `.tv` |
| Web (Railway) | https://intelwar-net-production.up.railway.app | hash `#org`/`#press`/`#net`/`#ai`/`#tv` |
| Log API | https://log-api-production-0798.up.railway.app | — |

Dashboard: https://railway.com/project/e451ab4d-a7f7-4a20-9c76-d652774e548b

**Frame:** `.org` is institutional home; `.press` is narrative spine. Instruments (`.net` / `.ai` / `.tv`) hang from that frame.

- **Instruments** (`.net` / `.ai` / `.tv`): Cloudflare → Railway custom domains on `intelwar-net` (DNS only + `_railway-verify` TXT).
- **Home / spine** (`.org` / `.press`): Cloudflare Worker `intelwar-edge` custom domains reverse-proxy the Railway SPA while preserving browser hostname (surface lock). Worker source: `intelwar/apps/intelwar-edge/`.

### Custom domain DNS — instruments (Cloudflare, DNS only / grey cloud)

Per zone (`intelwar.net` / `.ai` / `.tv`):

| Type | Name | Content |
|------|------|---------|
| CNAME | `@` | Railway-assigned `*.up.railway.app` target (Settings → Networking) |
| CNAME | `www` | Railway-assigned `*.up.railway.app` target for `www` |
| TXT | `_railway-verify` | `railway-verify=…` from Railway (**required** or edge 404) |
| TXT | `_railway-verify.www` | `railway-verify=…` for www |

Keep records **DNS only** (not proxied). After recreate, refresh CNAME + TXT from Railway before editing Cloudflare.

### Home / spine edge (`intelwar-edge`)

```bash
cd intelwar/apps/intelwar-edge
npx wrangler deploy   # attaches intelwar.org / .press (+ www) as Worker custom domains
```

## Services

| Service | Root | Public role |
|---------|------|-------------|
| `log-api` | `intelwar/services/log-api` | Living Log API + crosscheck verify + optional Kernel/DAG DB env gates |
| `intelwar-net` | `intelwar/apps/intelwar-net` | Public React shell (all brand surfaces) |
| `intelwar-edge` | `intelwar/apps/intelwar-edge` | Cloudflare Worker proxy for `.org` / `.press` |

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
# 3b) Deploy web — MUST use --path-as-root or the monorepo root
#     Dockerfile is built instead of the Node shell.
cd /path/to/exochain
railway up intelwar/apps/intelwar-net --path-as-root --service intelwar-net --ci -m "intelwar-net public shell"
railway domain --service intelwar-net

# 4) Instrument custom domains (DNS must point at Railway)
railway domain add intelwar.net --service intelwar-net

# 5) Home + spine via Cloudflare Worker (no Railway domain slot required)
cd intelwar/apps/intelwar-edge && npx wrangler deploy
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
