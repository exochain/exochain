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

# Node 0 — Genesis Deployment on Railway

## Overview

Node 0 is the **genesis node** of the EXOCHAIN network. It bootstraps the DAG, creates the first consensus round, and runs as the sole BFT validator until additional validators join. Railway provides managed Postgres, persistent volumes, GitHub-triggered deploys, and private networking — making it the fastest path from code to a live, persisted node.

This runbook gets Node 0 running from scratch. No prior Railway experience required.

---

## Prerequisites

- [ ] Railway account — sign up at [railway.com](https://railway.com)
- [ ] Railway CLI — `npm install -g @railway/cli`
- [ ] Railway authentication — `railway login` (opens browser)
- [ ] Git access to `github.com/exochain/exochain` (push to `main`)

---

## Step 1: Create Railway Project

```bash
railway init
```

When prompted:
- **Project name:** `exochain-node-0`
- **Link to existing repo:** select `github.com/exochain/exochain`

This creates the Railway project and links it to the repo. Pushes to `main` will trigger automatic deploys.

---

## Step 2: Add Postgres

```bash
railway add --database postgres
```

Railway provisions a Postgres 16 instance and automatically injects `DATABASE_URL` into your service environment over the private network. No manual connection string needed.

---

## Step 3: Add Persistent Volume

The node stores its SQLite DAG and identity key at `/data`. This volume **must** persist across restarts — losing it loses the chain.

**Via Railway dashboard:**
1. Project → `exochain` service → **Volumes** tab
2. **Add Volume** → Mount Path: `/data`

**Or via CLI:**
```bash
railway volume create exochain-data --mount-path /data
```

---

## Step 4: Set Environment Variables

```bash
railway variables --set "JWT_SECRET=$(openssl rand -hex 32)"
railway variables --set "EXOCHAIN_DATA_DIR=/data"
railway variables --set "RUST_LOG=info"
railway variables --set "IS_VALIDATOR=true"   # Genesis validator mode
# DATABASE_URL is injected automatically by the Postgres plugin
# PORT is auto-injected by Railway and consumed by entrypoint.sh
```

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes (auto) | Set by Railway Postgres plugin — private network URL |
| `JWT_SECRET` | Yes | 32+ byte random hex — JWT signing secret |
| `EXOCHAIN_DATA_DIR` | Yes | `/data` — persistent volume mount path |
| `IS_VALIDATOR` | Yes for Node 0 | `true` — entrypoint.sh adds `--validator` flag |
| `PORT` | Auto | Railway auto-injects; binary + entrypoint honor it |
| `P2P_PORT` | No | Default `4001`; override only for non-default routing |
| `RUST_LOG` | No | `info` for production; `debug` for troubleshooting |
| `SEED_ADDR` | No | Set on subsequent nodes joining the network |
| `VALIDATORS` | No | Comma-separated DIDs for explicit initial validator set |

---

## Step 5: Deploy

```bash
railway up
```

Railway builds the Dockerfile (multi-stage Rust + Node.js), starts the `exochain` binary, and runs the health check at `GET /health`. Build takes ~3–5 minutes on first run (Rust compile).

**Watch logs in real time:**
```bash
railway logs --tail
```

**What to look for:**
```
INFO exochain_node: Starting EXOCHAIN node
INFO exochain_node: Genesis block created
INFO exochain_node: Consensus reactor started (validator mode)
INFO exochain_node::network: Listening on 0.0.0.0:4001 (TCP) and 0.0.0.0:4002 (QUIC)
INFO exochain_node::api: HTTP API listening on 0.0.0.0:8080
```

---

## Step 6: Verify the Node is Live

```bash
# Open the Railway-assigned domain in your browser
railway open

# Or hit the health endpoint directly
curl https://<your-railway-domain>/health
# Expected: {"status":"ok","version":"..."}

# Check governance status
curl https://<your-railway-domain>/api/v1/governance/status
# Expected: {"consensus_round":0,"committed_height":0,"validator_count":1,"is_validator":true,...}
```

---

## Step 7: Run as Validator (Genesis Mode)

Node 0 must start as a BFT validator to bootstrap the network. The
Dockerfile's `entrypoint.sh` reads `IS_VALIDATOR=true` and adds the
`--validator` flag automatically. If you set `IS_VALIDATOR=true` in
Step 4, validator mode is already on — no further action needed.

**To verify:**
```bash
railway logs | grep "Consensus reactor"
# Expected: "Consensus reactor started (validator mode)"
```

**To toggle off (for read-only observer node):**
```bash
railway variables --set "IS_VALIDATOR=false"
```

**For an explicit multi-validator set (instead of just this node's DID):**
```bash
railway variables --set "VALIDATORS=did:exo:abc...,did:exo:def..."
```
The entrypoint will then pass `--validator --validators <list>` to the binary.

**CLI flags reference** (from `crates/exo-node/src/cli.rs`):

```
exochain start [OPTIONS]
  --api-port <PORT>         HTTP API port (default: 8080 via PORT env)
  --p2p-port <PORT>         P2P listen port (default: 4001)
  --data-dir <PATH>         Data directory (default: ~/.exochain)
  --validator               Run as BFT consensus validator
  --validators <DID,...>    Initial validator set DIDs (comma-separated)
                            If omitted, this node's DID is the sole validator
```

---

## Step 8: Verify DAG and Consensus State

```bash
# Check node status (requires running process in Railway)
railway run ./exochain status --data-dir /data
# Expected: height=0 (or 1 after genesis), peers=0 (standalone)

# Or via HTTP
curl https://<your-railway-domain>/api/v1/governance/status
```

Expected response when healthy:
```json
{
  "consensus_round": 1,
  "committed_height": 0,
  "validator_count": 1,
  "is_validator": true,
  "validators": ["did:exo:<node-0-did>"]
}
```

---

## Connecting a Second Node

Once Node 0 is running, additional nodes join via the `--seed` flag.

**Get Node 0's network address:**
```bash
# Railway assigns a public domain — use it as the seed on port 4001
# Example: exochain-node-0.up.railway.app:4001
```

**On Node 1 (different Railway project or service):**
```bash
exochain join \
  --seed exochain-node-0.up.railway.app:4001 \
  --data-dir /data \
  --validator
```

Or as a Railway start command:
```
./exochain join --seed <node-0-domain>:4001 --data-dir /data
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails | `railway logs --build` — look for Rust compile errors |
| Node exits immediately | `railway logs` — verify `DATABASE_URL` is set and Postgres is healthy |
| `DATABASE_URL` not found | Re-run `railway add --database postgres` and redeploy |
| Volume not mounting | Confirm `/data` mount in Railway dashboard → Volumes tab |
| Health check failing | Node may still be starting; allow up to 5 minutes on cold boot |
| Port conflicts | Railway exposes one external port — always use `PORT` env var |
| Consensus stuck at round 0 | In standalone mode with `--validator`, rounds advance only when proposals are submitted |

**Useful commands:**
```bash
railway logs                    # tail live logs
railway logs --build            # build-time logs (Rust compile output)
railway status                  # service status
railway variables               # list all env vars
railway shell                   # open a shell in the running container
```

---

## What Node 0 Proves

This is the genesis deployment. Once running:

- **DAG is live** — persisting to SQLite at `/data/dag.db`
- **Postgres connected** — governance artifacts stored via `PostgresStore`
- **BFT consensus bootstrapped** — standalone validator mode, ready for quorum expansion
- **Identity key generated** — node DID is committed and stored at `/data/identity.key`
- **Chain of custody is mathematically provable** — regardless of Railway's availability, the DAG hashes are the truth

When Node 1 joins and quorum reaches 4 validators (3f+1 BFT safety), the network becomes fully fault-tolerant.

---

## Ports Reference

| Port | Protocol | Purpose |
|---|---|---|
| `8080` | HTTP | API (`/health`, `/api/v1/...`, dashboard) |
| `4001` | TCP | P2P peer connections |
| `4002` | UDP/QUIC | P2P QUIC transport |

Railway exposes port `8080` externally via the assigned domain. Ports `4001` and `4002` are accessible via Railway's private network or public TCP proxy (configure in service settings if needed for multi-node).
