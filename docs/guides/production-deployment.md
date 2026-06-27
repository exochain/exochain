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

# Production Deployment Guide

This guide covers deploying the EXOCHAIN gateway to a production-like environment
with a live PostgreSQL database and the `production-db` feature enabled.

---

## Prerequisites

| Requirement | Minimum version | Notes |
|-------------|----------------|-------|
| Rust toolchain | 1.85 (MSRV) | Install via [rustup](https://rustup.rs/) |
| Docker | 24+ | For Postgres and container builds |
| Docker Compose | v2 plugin | `docker compose` (not `docker-compose`) |
| PostgreSQL | 14+ | Hosted or self-managed; 16-alpine recommended |
| sqlx-cli | latest | `cargo install sqlx-cli --no-default-features --features postgres,rustls` |

---

## Docker Compose Setup

The repository ships `docker-compose.yml` for local development.  For production
or staging, create your own `docker-compose.prod.yml` along the following lines:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: exochain
      POSTGRES_USER: exochain
      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"   # inject from env or secrets
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U exochain -d exochain"]
      interval: 5s
      timeout: 5s
      retries: 12
      start_period: 10s

  exochain-gateway:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: "postgres://exochain:${POSTGRES_PASSWORD}@postgres:5432/exochain"
      BIND_ADDRESS: "0.0.0.0:8080"
      LOG_LEVEL: info
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

volumes:
  pgdata:
```

Start the stack:

```bash
POSTGRES_PASSWORD=<your-secret> docker compose -f docker-compose.prod.yml up -d
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes (production) | — | PostgreSQL URL; required for production AVC registry durability and `/ready` |
| `EXO_AVC_REQUIRE_POSTGRES_DURABILITY` | Recommended (production) | `false` | Set to `true` or `1` to abort startup when `DATABASE_URL` is missing |
| `EXO_AVC_ROOT_TRUST_BUNDLE` | Yes (production AVC root trust) | Docker image default | Verified root trust bundle path used to restore AVC public-key trust anchors at startup |
| `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND` | Yes (strict AVC receipt proof) | `json-ed25519` | Set to `rfc3161` for Microsoft Azure Artifact Signing TSA |
| `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL` | Yes (strict AVC receipt proof) | — | RFC 3161 endpoint; Microsoft production value is `http://timestamp.acs.microsoft.com` |
| `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID` | Yes (strict AVC receipt proof) | — | Authority DID; Microsoft production value is `did:exo:microsoft-public-rsa-tsa` |
| `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX` | Yes (strict AVC receipt proof) | — | Pinned TSA signer SPKI DER hex values from live preflight; use a comma-separated set when Microsoft returns multiple signer keys |
| `EXO_AVC_RFC3161_TIMESTAMP_POLICY_OID` | Yes (strict AVC receipt proof) | — | Microsoft Azure Artifact Signing policy OID `1.3.6.1.4.1.601.10.3.1` |
| `EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY` | Yes (strict AVC receipt proof) | `false` | Set to `true` to fail closed when RFC 3161 proof is absent or unverifiable |
| `BIND_ADDRESS` | No | `127.0.0.1:8443` | Host and port the gateway listens on |
| `LOG_LEVEL` | No | `info` | Tracing filter: `trace`, `debug`, `info`, `warn`, `error` |

`DATABASE_URL` follows the standard PostgreSQL connection URI format.  Example:

```
postgres://exochain:secret@localhost:5432/exochain
```

For production AVC registry durability, `DATABASE_URL` must point to a reachable
PostgreSQL instance. Without it, the node uses the local AVC file fallback under
the node data directory and emits a production durability warning; that fallback
is not a substitute for Postgres-backed production durability. Set
`EXO_AVC_REQUIRE_POSTGRES_DURABILITY=true` in production to fail startup instead
of accepting the fallback.

AVC public-key trust anchors are not persisted in the AVC registry durable state.
They are restored on every boot from the verified
`EXO_AVC_ROOT_TRUST_BUNDLE` startup configuration, then durable revocations are
revalidated against those live trust anchors.

For production civilizational-class AVC receipt proof, use the Microsoft RFC 3161
authority record ratified in
`governance/resolutions/CR-004-AVC-TIMESTAMP-FINALITY-AUTHORITY.md`.
Run the live preflight before setting or rotating the pinned SPKI set:

```bash
EXO_AVC_RFC3161_LIVE_PREFLIGHT=1 ./tools/avc_rfc3161_microsoft_preflight.sh
```

Current Railway production values from the June 27, 2026 preflights. Microsoft
returned two valid signer SPKIs from the same RFC 3161 endpoint, so the
production pin value is comma-separated:

```bash
railway variables --set "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND=rfc3161"
railway variables --set "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL=http://timestamp.acs.microsoft.com"
railway variables --set "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID=did:exo:microsoft-public-rsa-tsa"
MICROSOFT_TSA_SPKI_PINS="30820222300d06092a864886f70d01010105000382020f003082020a0282020100b4a59f9bfba5d36eff77c4656fc327fe0d1052fbcba98d95b32ded23c536b454aca53668999383dc11d3f0b911f91ae130981bd558c0285372b1a2bd70b49789f3c648806b3c282cf4fe32db896b2449ab57a439cf8066a8c8483eb66112f6675a9092e073bb8d849e8bf9f1982effd44afe9792e0dcf992c5bf1dd8855c011c52c350789b107a5c8d2791e97dc1ad5d61bdb07c6a687eb6859b164ec53f5e361b782c7d1105256e79b6ba64da634bfd20b5f9bbaa2222c8fea9e8f4734d36cc9d5aac1e757f77fad6d331f1f90f90359e7052a2a64d9241f6153ce77fb6a57e6b0df2b7dae358f7f5813809b36ea82911d4246e231abd43325034a19b2708be01dd4274b6d3bb138fc33e9092f7b4e75a84fb8fa8cc2c6820a075fc30431d0ef5329eec54af6c0118b3502795d0a5fca1c6642395bd436a8f22f5d092ded3ff860fdff29ea5c6585a573a36ae9ef67f70a44e8633783397bac71d1bda68aa70f8a2e3f8a2d9985e29a9652444fb08a96915286cdf0ca0e85fdfa2343142f3e76d60f8372c7a9618d68f09a82dcc7ac351520ad6af2c2972df704b452953538a8a53169af1ded837b12aa67f573b4498d2e98ebca157ad61fbaf197ef626a2722b5d9d34e4b009d18ef7a474a4f7960ee544c7e67d953cbd73623745182734fd123aa3466d2e37f874a17c4f84d7cf62a7856f23d7186c73698533eb3c77a9370203010001"
MICROSOFT_TSA_SPKI_PINS="$MICROSOFT_TSA_SPKI_PINS,30820222300d06092a864886f70d01010105000382020f003082020a02820201009d7834a47690ecf5409659fe1d966b24570ba0a6de9215b5c8bf9034152014552c8d920a6aaa8de28209b09337a6cd2b24d48eee7742351b990d7d9682eaf7024efb797ae5a015ea6663ba6555de0cd4422e5756e00d3f35f8f327b5d791d1218ebf358215c4a51ef30bec1b68d37eb0f4b1ccb01905e89b0c53fb5f0b39c17d19b48b0dd5adbe5eae5bbd6a77911332b70b244e3ba746078b64bfed069db7ec955d44f14043d8d844aa42a94068fefd718c12d1095dcf6a52a39c67dbdcc37853b8d5caa89f1474a17275b9084451a019946bab32803cc54abf1ede0f774cf34b1548af504d0698b7db5f971e0f51add45719eb1fc92d5013ce4e7e0561db331c092159153d3a9248c8d0e8a4ca75c9eade91f4738005269fe096f729ab453d7f36488c9186bdda62b2195197bed142d5214a3c47bc29f72c2ff1a904303874900ec1a1e8d5f60f445fb12c84b53001c8069efb6c351c1c930d372695334b12e40b7828f580d05d2168f458e6320ed8e343ff224d663a7b2d6f6fda87963223e478089dd4f93fd318936560d9eee129464d04d6c0fe1b2006cba867e217f3d5af8c437d69b17dd52e0e255ba29e62ac2cefcc2db9e5ee292e0f474dea803461ec320d09dcb35dac33d1ceb6eef6400fd366579fbd6f2bf71b4c5c06284257068ec93c5b851cedc7ea56a6c83e376873c6710732dc5dc5723f8a797322f0be430203010001"
railway variables --set "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX=$MICROSOFT_TSA_SPKI_PINS"
railway variables --set "EXO_AVC_RFC3161_TIMESTAMP_POLICY_OID=1.3.6.1.4.1.601.10.3.1"
railway variables --set "EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY=true"
```

The node applies a 10-second HTTP timeout to the timestamp authority request and
does not retry inside receipt emission. Operators may retry the same emission
request; receipt idempotency prevents duplicate divergent receipts.

---

## Running Migrations

Migrations live in `crates/exo-gateway/migrations/` and are managed by
[sqlx-migrate](https://docs.rs/sqlx/latest/sqlx/macro.migrate.html).

Apply all pending migrations against your database:

```bash
export DATABASE_URL="postgres://exochain:secret@localhost:5432/exochain"
sqlx migrate run --source crates/exo-gateway/migrations
```

Migrations are also applied automatically at startup when the gateway is
compiled with the `production-db` feature and `DATABASE_URL` is set, via the
`db::init_pool` function.

To inspect applied migrations:

```bash
sqlx migrate info --source crates/exo-gateway/migrations
```

---

## Feature Flags

### `production-db`

The gateway ships with a **WO-009 deny-all scaffold** as the default
adjudication context.  This means every adjudication request is denied until a
live database is configured — a safe default for development and testing.

Enable the production DB resolver by compiling with the `production-db` Cargo
feature:

```bash
cargo build --release --features exo-gateway/production-db
```

Or in Docker (add to `Dockerfile` build args / `ENV`):

```dockerfile
RUN cargo build --release --features exo-gateway/production-db
```

**When to enable**: only when `DATABASE_URL` points to a fully-migrated
PostgreSQL instance with `agent_roles`, `consent_records`, and
`authority_chains` tables populated.  Without populated adjudication tables the
DB resolver returns the same deny-all context as the scaffold.

**When NOT to enable**: local development without Docker, CI unit-test jobs
(Gates 1–12), or environments where you intentionally want deny-all behavior.

---

## Health Checks

The gateway exposes two health endpoints:

### `GET /health`

Always returns `200 OK` with basic version and uptime information.  Use this
as the liveness probe in Kubernetes / Docker Compose.

```bash
curl -s http://localhost:8080/health | jq .
# {"status":"ok","version":"0.1.0-beta","uptime_seconds":42}
```

### `GET /ready`

Returns `200 OK` when the PostgreSQL pool is reachable, `503 Service
Unavailable` otherwise.  Use as the readiness probe.

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ready
# 200  (DB reachable)
# 503  (DB unavailable or DATABASE_URL not configured)
```

Docker Compose readiness example:

```yaml
healthcheck:
  test: ["CMD-SHELL", "curl -sf http://localhost:8080/ready || exit 1"]
  interval: 10s
  timeout: 5s
  retries: 6
  start_period: 15s
```

---

## Smoke Test

Once the stack is running and migrations are applied, verify end-to-end
operation by registering a DID:

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "id": "did:exo:smoke-test-001",
    "public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "created_at": 0
  }' | jq .
# {"did":"did:exo:smoke-test-001","status":"registered"}
```

A `201 Created` response confirms the gateway is accepting requests and writing
to the DID registry.  A `503` on `/ready` or a `500` here indicates a database
connectivity problem — check `DATABASE_URL` and that migrations have run.
