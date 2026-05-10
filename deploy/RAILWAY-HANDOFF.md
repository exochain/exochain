<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Node 0 Railway Deployment — Handoff

**Status:** Code is deployment-ready. Manual Railway CLI steps remain.

**Your Pro account capacity:** up to 42 replicas at 24 vCPU / 24 GB RAM each, 1 TB storage. Start small (recommend 1 replica, 2 vCPU, 4 GB RAM, 10 GB volume) and scale as load demands.

---

## Pre-flight: Code is ready

PR [#92](https://github.com/exochain/exochain/pull/92) merged to `main` — fixes:

1. Dockerfile builds the right binary (`exochain` + `exo-gateway`, not the missing `decision-forum-server`)
2. Rust version pinned to 1.85 (matches workspace)
3. Binary respects Railway's auto-injected `$PORT` env var
4. Dockerfile invokes `entrypoint.sh` (env-var driven, idiomatic)
5. `railway.json` no longer overrides start command (entrypoint runs)

Smoke-verified: `PORT=9999 exochain start` binds to 9999, `/health` returns `{"status":"ok"}`.

---

## What you need to do

### 1. Authenticate (one-time)

```bash
railway login
```

(Opens browser. The token in our chat is project-scoped read-only — insufficient for deploys. Use your account session.)

### 2. Link the existing project

```bash
cd /Users/bobstewart/dev/exochain
railway link --project ca52ac39-820a-488b-8f29-df17d76a9270
```

Choose `production` environment when prompted.

### 3. Add Postgres

```bash
railway add --database postgres
```

Railway provisions a Postgres 16 instance and auto-injects `DATABASE_URL` over the private network.

### 4. Add a service (the exochain node)

```bash
railway add --service exochain --repo exochain/exochain
```

Or link the local directory:
```bash
railway service create exochain
```

### 5. Set environment variables on the exochain service

```bash
railway variables --service exochain \
  --set "JWT_SECRET=$(openssl rand -hex 32)" \
  --set "EXOCHAIN_DATA_DIR=/data" \
  --set "RUST_LOG=info" \
  --set "IS_VALIDATOR=true"
```

(`PORT` is auto-injected by Railway. `DATABASE_URL` is auto-injected by the Postgres plugin.)

### 6. Mount persistent volume at /data

**Via dashboard** (faster): Project → `exochain` service → **Volumes** → **+ Add Volume** → mount path `/data` → 10 GB.

**Or via CLI:**
```bash
railway volume create --service exochain --mount-path /data --size 10
```

### 7. Configure the custom domain

```bash
# Generate Railway-default domain first (for testing)
railway domain --service exochain

# Then add your custom domain
railway domain --service exochain --custom node.exochain.io
```

You'll get instructions to add a CNAME record at your DNS provider pointing `node.exochain.io` → `<railway-assigned>.up.railway.app`.

### 8. Configure TCP proxy on port 4001 (P2P)

```bash
railway tcp-proxy --service exochain --port 4001
```

This gives you a public TCP address like `roundhouse.proxy.rlwy.net:12345` that maps to the container's `4001`. Other nodes will use this as `--seed`.

### 9. Deploy

```bash
railway up
```

Or, since you'll have GitHub auto-deploy enabled (via dashboard → service → Settings → Source → GitHub), every merge to `main` triggers a deploy automatically. To do a one-off manual deploy:

```bash
railway redeploy --service exochain
```

### 10. Watch the logs

```bash
railway logs --service exochain
```

**Look for:**
```
INFO exochain: Node identity ready did=did:exo:...
INFO exochain: DAG store opened height=0
INFO exochain: Starting exochain node api_port=8080 p2p_port=4001 validator=true
INFO exochain: Consensus reactor started (validator mode)
INFO exochain: Dashboard at http://localhost:8080
```

### 11. Verify it's live

```bash
# Health
curl https://node.exochain.io/health
# Expected: {"status":"ok","version":"...","uptime_seconds":N}

# Governance status
curl https://node.exochain.io/api/v1/governance/status
# Expected: {"consensus_round":0,"committed_height":0,"validator_count":1,"is_validator":true,...}

# All 6 MCP resources via the embedded MCP server (if you also expose it)
# (See docs/guides/mcp-integration.md)
```

---

## CI/CD setup (Step E from your spec)

To wire ExoForge auto-deploy on `main`:

1. Dashboard → service `exochain` → **Settings** → **Source** → **Connect Repo**
2. Select `exochain/exochain` → branch `main`
3. Enable **Automatic Deployments**

Now every PR merged to `main` → Railway builds + deploys automatically.

For dev/stage/prod (your roadmap goal):
```bash
railway environment create staging
railway environment create development
```

Each environment gets its own Postgres + volume + URL. Promotion flow: branch `develop` → `staging` env → branch `main` → `production` env.

---

## What to monitor after first deploy

| Check | Frequency | Expected |
|-------|-----------|----------|
| `GET /health` | Every 30s (Railway healthcheck) | 200 OK |
| `GET /api/v1/governance/status` | Manual | `is_validator: true`, `consensus_round` increments slowly |
| Memory usage | Dashboard | <500 MB at idle, grows with DAG size |
| CPU | Dashboard | <5% at idle |
| Volume usage | Dashboard | DAG grows ~10 KB per event |
| Postgres connections | Dashboard | <10 typically |

---

## When you wake up: rotate the burned token

The `b30f...` token in our transcript is now compromised. Rotate it:

1. https://railway.com/account/tokens
2. Click **Revoke** on the token
3. Generate a new one if needed for ExoForge or other automation

---

## What's already in the code

- `Dockerfile` — multi-stage build (Rust 1.85 + Node 20), bundles entrypoint.sh
- `deploy/entrypoint.sh` — reads `IS_VALIDATOR`, `SEED_ADDR`, `EXOCHAIN_DATA_DIR`, `PORT`, `P2P_PORT`, `VALIDATORS`
- `railway.json` — Dockerfile builder, healthcheck `/health`, restart on failure
- `crates/exo-node/src/main.rs` — `Command::Start` and `Command::Join` honor `$PORT` env

---

## Reference: All the runbooks and guides

- [`deploy/NODE-ZERO.md`](./NODE-ZERO.md) — comprehensive runbook (this file's longer cousin)
- [`docs/guides/mcp-integration.md`](../docs/guides/mcp-integration.md) — MCP server integration
- [`docs/guides/sdk-quickstart-rust.md`](../docs/guides/sdk-quickstart-rust.md) — Rust SDK
- [`docs/guides/architecture-overview.md`](../docs/guides/architecture-overview.md) — system architecture

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
