# IntelWar Railway Deploy (Kernel-required)

**Classification:** Adjacent public shell calling real Kernel bins — no trust by proximity beyond proven gates.  
**Branch:** `intelwar`  
**Project:** `intelwar` (`e451ab4d-a7f7-4a20-9c76-d652774e548b`) · env `production`

## Live URLs

| Surface | URL | Host locks to |
|---------|-----|----------------|
| Home | https://intelwar.org | `.org` |
| Spine | https://intelwar.press | `.press` |
| Living Log | https://intelwar.net | `.net` |
| Adversary | https://intelwar.ai | `.ai` |
| Provenance | https://intelwar.tv | `.tv` |
| Log API | https://log-api-production-0798.up.railway.app | Kernel-required |

## Fail-closed rules

1. **Simulated append/verify removed.** Missing bins → HTTP 503.
2. **`INTELWAR_CORE_BIN` + `INTELWAR_CROSSCHECK_BIN` required** (image sets paths under `/app/native/`).
3. **`INTELWAR_CROSSCHECK_SIGN_BIN` + `INTELWAR_DEMO_CHECKER_SK_HEX`** for UI sign-demo.
4. **`INTELWAR_CORE_STATE_DIR`** on a durable volume (`/data/intelwar-bridge-state`).
5. DAG DB: all-or-nothing when URL set; intake failure → 503; success → `durable: dagdb`, else `local_kernel`.
6. Web still requires `VITE_LOG_API_URL` at build time.

## Deploy log-api (Kernel image — Linux multi-stage on Railway)

```bash
# From repo root — pack slim monorepo context (builds bins on Railway Linux)
bash intelwar/services/log-api/scripts/pack-railway-context.sh
# STAGE defaults to /tmp/intelwar-log-api-railway-ctx

# Secrets (never commit):
# openssl rand -hex 32  → INTELWAR_DEMO_CHECKER_SK_HEX
railway variable set \
  INTELWAR_CORE_STATE_DIR=/data/intelwar-bridge-state \
  INTELWAR_DEMO_CHECKER_DID=did:exo:crosscheck-peer \
  INTELWAR_DEMO_CHECKER_SK_HEX="<64-hex>" \
  --service log-api

# Attach a volume at /data for bridge state (Railway UI).
# Optional frontier adversarial (intelwar.ai):
# railway variable set OPENROUTER_API_KEY="<key>" --service log-api

cd /tmp/intelwar-log-api-railway-ctx
railway up . --path-as-root --service log-api --ci --no-gitignore \
  -m "Kernel-required log-api"
```

Image sets:
- `INTELWAR_CORE_BIN=/app/native/intelwar-log-append`
- `INTELWAR_CROSSCHECK_BIN=/app/native/intelwar-crosscheck-verify`
- `INTELWAR_CROSSCHECK_SIGN_BIN=/app/native/intelwar-crosscheck-sign`

## Deploy intelwar-net

```bash
railway up intelwar/apps/intelwar-net --path-as-root --service intelwar-net --ci \
  -m "Kernel-honest shell"
```

Must use `--path-as-root` or the monorepo root Dockerfile is built instead.

## Validation

```bash
curl -fsS "$API/health" | jq .
# expect status ok, kernel_bridge_configured true, trust_claim kernel_local
curl -fsS -X POST "$API/api/consent/grant" -H 'content-type: application/json' -d '{}'
curl -fsS -X POST "$API/api/log/append" -H 'content-type: application/json' \
  -d '{"summary":"kernel live","voice_kind":"human"}' | jq .entry.simulated
# expect false
```

See also: `intelwar/docs/BRIDGE_TRUST_MODEL.md`.
