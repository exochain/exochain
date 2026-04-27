# Remediation Plan — Review 2026-04-19

Findings: [REVIEW-2026-04-19.md](./REVIEW-2026-04-19.md)

**Ordering principle.** Each wave either (a) unblocks parallel work in later waves, (b) removes a correctness/security hazard that invalidates other work if deferred, or (c) catches regressions for work already shipped. Within a wave, the listed tracks are independent — parallelize freely.

---

## Wave 0 — Foundation

| ID     | Unit                                                                             | Files                                     | Acceptance                                                       | Status        |
| ------ | -------------------------------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------- | ------------- |
| A-001  | Commit this review + plan                                                        | `docs/audit/REVIEW-2026-04-19*.md`        | Findings linkable from every follow-up PR                         | **this PR**   |
| A-002  | ~~Downgrade `edition = "2024"` → `2021`~~                                        | `Cargo.toml:27`                           | DROPPED — edition 2024 stable since 1.85; MSRV 1.85, fine         | dropped       |
| A-003  | ~~Pin toolchain: `rust-toolchain.toml` at repo root, channel `1.88`~~            | repo root                                 | DROPPED — CI intentionally tracks current stable; Dockerfile pins deploy floor | dropped       |
| A-004  | CI gate audit                                                                    | `.github/workflows/ci.yml`                | 22 gates verified blocking, no `continue-on-error`                | verified      |

## Wave 1 — Correctness + security-critical (parallel)

Four independent tracks. All must land before any production deploy.

### Track 1a — Consensus/DAG correctness

| ID     | Unit                                                                              | File:line                                    |
| ------ | --------------------------------------------------------------------------------- | -------------------------------------------- |
| A-010  | Fix div-by-zero in convergence scoring + property test                            | `crates/exo-consensus/src/scoring.rs:83`     |
| A-011  | Return `Result` from sig encode/decode in PG store                                | `crates/exo-dag/src/pg_store.rs:83, 88`      |
| A-012  | Replace `as u64`/`as u32` casts with `try_into`; reject negative timestamps       | `crates/exo-dag/src/pg_store.rs:127`         |
| A-013  | Replace `unwrap_or(u64::MAX)` on time conversion with explicit error              | `crates/exo-dag/src/append.rs:40-41`         |

### Track 1b — MCP + gateway input hardening

| ID     | Unit                                                                              | File:line                                                          |
| ------ | --------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| A-020  | Validate `tools/call` params against registered `input_schema`                    | `crates/exo-node/src/mcp/handler.rs:199-278`                      |
| A-021  | Replace `.unwrap()` on JSON serialization in hot paths                            | `handler.rs:110, 119`, `tools/node.rs:100, 295, 309, 330`          |
| A-022  | `tower_http::limit::DefaultBodyLimit::max(1 MiB)` on gateway router               | `crates/exo-gateway/src/server.rs`                                 |
| A-023  | Scrub error leaks (no "mutex poisoned" strings to clients)                        | `crates/exo-node/src/mcp/tools/node.rs:78`                         |

### Track 1c — Web auth + XSS

| ID     | Unit                                                                               | File:line                                              |
| ------ | ---------------------------------------------------------------------------------- | ------------------------------------------------------ |
| A-030  | Replace regex markdown with `markdown-to-jsx` or DOMPurify-sanitized HTML          | `web/src/…/CouncilAIPanel.tsx:86`                      |
| A-031  | Kill dev bypass from production bundle — build-time guard + assert-absent in build | `web/src/…/auth.tsx:69-86`                             |
| A-032  | Add CSP `<meta>`; document httpOnly cookie plan for access token                   | `web/index.html`                                       |
| A-033  | Remove 3 stale `vitest.config.ts.timestamp-*.mjs`; add to `.gitignore`             | `web/`, `.gitignore`                                   |

### Track 1d — Deploy surface

| ID     | Unit                                                                              | File:line                |
| ------ | --------------------------------------------------------------------------------- | ------------------------ |
| A-040  | Harden root `Dockerfile`: `USER exochain`, `HEALTHCHECK`, exec-form `ENTRYPOINT`  | `Dockerfile`             |
| A-041  | `init-db.sh`: `IF NOT EXISTS`, `set -euo pipefail`, idempotency test               | `init-db.sh`             |
| A-042  | `railway.json` healthcheck timeout 300 → 15s                                       | `railway.json:10`        |
| A-043  | Scrub hardcoded dev secrets from `docker-compose.yml` → `.env.example` with warnings | `docker-compose.yml`     |

## Wave 2 — Parity + hardening (parallel; depends on W1)

### Track 2a — DID derivation unification (**BREAKING**)

| ID     | Unit                                                                                                |
| ------ | --------------------------------------------------------------------------------------------------- |
| A-050  | Canonical = BLAKE3 (matches chain-native `exo-core` hash); emit cross-language test vectors file    |
| A-051  | TS SDK: switch to `@noble/hashes/blake3`                                                            |
| A-052  | Python SDK: switch to `blake3` package                                                              |
| A-053  | CHANGELOG + SDK README breaking-change notice; coordinate version bump                              |

### Track 2b — SDK parity

| ID     | Unit                                                                                                 |
| ------ | ---------------------------------------------------------------------------------------------------- |
| A-060  | Align operation names across TS/Python/Rust (canonical = Rust names); deprecation aliases for 1 release |
| A-061  | Python: configurable `httpx.Timeout` per client; `TransportError` carries status + body              |
| A-062  | TS: add Zod runtime validation for all payload shapes                                                |
| A-063  | Python: `py.typed` marker + typed return models (replace `dict[str, Any]`)                           |
| A-064  | TS: add dual CJS/ESM exports or doc ESM-only explicitly                                              |
| A-065  | Complete WASM SDK: `wasm-pack` build script, TS types, publishable `package.json`                    |
| A-066  | Version-skew handling: embed `PROTOCOL_VERSION`, client pings `/version` on init                     |

### Track 2c — Runtime lifecycle

| ID     | Unit                                                                                                       |
| ------ | ---------------------------------------------------------------------------------------------------------- |
| A-070  | SIGTERM/SIGINT handler + `CancellationToken` wiring; graceful drain with timeout                            |
| A-071  | Rate limiting: per-actor + global call budget in MCP middleware; tower rate-limit on gateway                |
| A-072  | Replace mocked `McpContext`/`AdjudicationContext` with live `NodeContext` (**needs running node or flag**) |
| A-073  | Wire reactor events into the SSE stream (replace placeholder heartbeat)                                    |

### Track 2d — Web tests + CSRF

| ID     | Unit                                                                                                  |
| ------ | ----------------------------------------------------------------------------------------------------- |
| A-080  | Expand `vitest` coverage to `src/pages/**` + `src/components/**` (target ≥70% on critical paths)       |
| A-081  | Resolve `UNMET DEPENDENCY playwright@^1.59.1` — install + wire smoke test, or remove                  |
| A-082  | CSRF tokens on mutating requests; doc server-side pattern (SameSite=Strict or double-submit)          |
| A-083  | A11y: labels on icon-only buttons + status badges; `aria-live="polite"` on status                     |

## Wave 3 — Hygiene + ops

| ID     | Unit                                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------------------- |
| A-090  | Dep hygiene sprint (APE-12): migrate off `ring 0.16`; single `ring 0.17` across lock                          |
| A-091  | `async-graphql` upgrade path: MSRV bump to 1.89 plan; release note                                            |
| A-092  | `verify_hybrid` accepts `&[u8]` (no clone)                                                                     |
| A-093  | `SECURITY.md`: operationalize endpoint OR switch to GitHub Security Advisories (recommended)                   |
| A-094  | `.env.example` expansion — audit every `env::var` / `process.env.*` read                                       |
| A-095  | Pre-commit secret scan (`gitleaks`) in CI                                                                      |
| A-096  | Delegation expiry clock-tolerance doc                                                                          |
| A-097  | Systemd unit: confirm ExecStart binary traps SIGTERM (verified via A-070); tighten hardening                   |

## Wave 4 — Formalism + doc debt

| ID     | Unit                                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------------------- |
| A-100  | TLA+ in CI: `tlc` gate over `tla/*.tla`                                                                       |
| A-101  | `verify_nist_mapping()` test: every `NIST_AI_RMF_MAPPING.toml` entry points to a reachable function           |
| A-102  | GAP-REGISTRY CI stub-check: `grep -rn "TODO.*GAP-00[0-9]\|STUB.*GAP" crates/ packages/`                         |
| A-103  | Convergence scoring: replace hardcoded `assert_eq!(score, 3333)` with `proptest`                               |
| A-104  | Doc-rot sweep: update `spec v2.1` refs → `v2.2`; update PRD version refs                                       |
| A-105  | CHANGELOG refresh: dated entry + `[Unreleased]` section                                                        |
| A-106  | Council panel PRDs: add `Last Verified` header                                                                 |
| A-107  | `CONTRIBUTING.md`: cross-link to `docs/guides/DEPLOYMENT.md`                                                   |
| A-108  | `pg_store` schema version sentinel for future migrations                                                       |

## Dependency graph

```
W0 (A-001..004) ──┬─► W1a (consensus/DAG)
                  ├─► W1b (MCP/gateway) ──► W2c (shutdown + rate limit + NodeContext)
                  ├─► W1c (web XSS/auth) ──► W2d (web tests + CSRF)
                  └─► W1d (deploy) ──┐
                                      ▼
                     W2a (DID unification — BREAKING)  ◄── needs sign-off
                     W2b (SDK parity)                  ◄── independent
                                      │
                     W3 (hygiene + ops) ◄── needs W1+W2
                     W4 (formalism + docs) ◄── independent, polish sprint
```

## Estimated cadence

- Wave 0: ~1 day, 1 engineer — **in flight**
- Wave 1: ~1 week, 4 parallel PRs — ship-blocking
- Wave 2: 1–2 weeks, 4 parallel tracks
- Wave 3: ~1 week, parallel with W2 tail
- Wave 4: 3–5 days, any time after W1

Total calendar ≈ 3–4 weeks with 2–4 engineers; critical path is W0 → W1b → W2c.
