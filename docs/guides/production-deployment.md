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
| `DATABASE_URL` | Yes (production) | — | `postgres://<user>:<pass>@<host>:<port>/<db>` |
| `BIND_ADDRESS` | No | `127.0.0.1:8443` | Host and port the gateway listens on |
| `LOG_LEVEL` | No | `info` | Tracing filter: `trace`, `debug`, `info`, `warn`, `error` |

`DATABASE_URL` follows the standard PostgreSQL connection URI format.  Example:

```
postgres://exochain:secret@localhost:5432/exochain
```

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
