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

# Gauntlet Gateway Surface Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet gateway and HTTP-surface findings. The source artifacts remain imported
evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`
- `/Users/bobstewart/Library/Mobile Documents/com~apple~CloudDocs/Exochain-audit-report-run2.html`

Validation target:

- branch: `main`
- commit: `068468e8a6876a406b6317ba8e7ed14adf45d626`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | HTTP gateway routing, middleware, request validation, metrics, and handler dispatch. |
| `crates/exo-gateway/src/rest.rs` | Core runtime adapter | Canonical non-GraphQL REST route inventory. |
| `crates/exo-gateway/src/handlers.rs` | Core runtime adapter | Decision-forum vote and adjudication handlers behind the gateway. |
| `crates/exo-gateway/src/db.rs` | Core runtime adapter | Durable gateway persistence helpers and migration checks. |
| `crates/exo-gateway/src/main.rs` | Core runtime adapter | Gateway process initialization and structured logging setup. |
| `docs/audit/GAUNTLET-GATEWAY-SURFACE-VALIDATION-2026-05-15.md` | EXOCHAIN core governance artifact | Current validation record for imported gateway-surface evidence. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |
| `/Users/bobstewart/Library/Mobile Documents/.../Exochain-audit-report-run2.html` | Imported evidence | Read-only external assessment artifact. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-058 no CORS policy on the external gateway | Not reproduced as a permissive-CORS exposure | Current gateway code contains no `CorsLayer`, wildcard `Access-Control-Allow-Origin`, or broad allow-origin configuration. Browser cross-origin access is therefore not silently enabled by default. If a browser client later needs CORS, it should use an explicit allow-list with tests rather than a wildcard policy. |
| F-060 `POST /api/v1/decisions` wired to `vote_handler` | Stale / already remediated | The live router maps `POST /api/v1/decisions` to `handle_decision_create`; a source guard rejects dispatching this route to `vote_handler`. |
| F-061 layout-template `PUT` partially validates input | Stale / already remediated | Layout-template upsert validates top-level fields, builtin claims, canonical array layout, item geometry, optional flags, duplicate IDs, and hidden panels before persistence. |
| F-062 inconsistent error response envelope | Security-relevant leakage path already remediated | Internal 5xx paths log server-side details and return generic client errors. DB-unavailable responses use a generic client message. Full API envelope normalization remains product API cleanup, not a reproduced core trust bypass in this slice. |
| F-063 HTTP status code misuse | Stale for checked gateway paths | Runtime tests cover 401 before unauthenticated registry reads, 429 for gateway rate limiting, 501 for intentionally unavailable legal endpoints, 503 for DB-unavailable paths, and non-404 responses for all enumerated REST routes. |
| F-064 route count claim does not match enumerated routes | Stale / already remediated | `RestRoute::all()` enumerates the live non-GraphQL gateway surface, including metrics, identity, pace, layout, and constitutional routes; the route inventory test confirms the live count and paths. |
| F-065 `load_conflict_declarations` returns empty data | Stale / already remediated | Conflict declaration loading is DB-backed and fails closed when no DB pool is configured; payload validation rejects wrong actors and placeholder content. |
| F-066 `handle_advance_pace` persists nothing | Stale / already remediated | Authorized pace advancement persists to `db::update_agent_pace` or `db::update_user_pace` after authenticating the session actor and adjudicating the request. |
| F-067 bare `tracing_subscriber::fmt::init()` | Stale / already remediated | Gateway initialization uses `EnvFilter::try_from_default_env`, attaches the filter, and emits JSON-formatted tracing output. |
| F-068 no request tracing spans | Stale / already remediated | `TraceLayer::new_for_http()` is attached to the gateway router. |
| F-073 no HTTP metrics endpoint | Stale / already remediated | `/gateway/metrics` returns Prometheus text and omits raw secrets, tokens, DIDs, connection strings, and env-var names. |
| F-115 file-upload MIME confusion | Not reproduced in owned gateway code | No multipart or file-upload handler exists in `crates/exo-gateway/src`. Gateway request bodies are capped with `DefaultBodyLimit`, and DID-document routes have tighter explicit body limits. |
| F-118 missing browser security headers | Stale / already remediated | `attach_gateway_security_headers` is applied to every gateway response through `apply_gateway_layers`, including CSP and related browser-facing hardening headers. |
| F-119 in-memory rate limiter as only control | Reframed as bounded admission control | The gateway limiter is deterministic, HLC-backed, socket-IP keyed, and protected by a global concurrency cap. It is an admission-control guard, not a durable tenant quota system; no core trust decision relies on it as authority. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-gateway gateway_ -- --nocapture
cargo test -p exo-gateway layout_template_ -- --nocapture
cargo test -p exo-gateway conflict_declaration_ -- --nocapture
cargo test -p exo-gateway advance_pace_handler_ -- --nocapture
cargo test -p exo-gateway decision_post_route_dispatches_to_create_handler_not_vote_handler -- --nocapture
cargo test -p exo-gateway vote_handler_source_does_not_default_conflict_adjudication -- --nocapture
cargo test -p exo-gateway init_pool_uses_structured_tracing_not_stdout -- --nocapture
cargo test -p exo-gateway defined_api_routes_return_non_404 -- --nocapture
cargo test -p exo-gateway internal_http_errors_do_not_expose_display_strings_to_clients -- --nocapture
rg -n "CorsLayer|Access-Control-Allow-Origin|allow_origin|CORS|cors" crates/exo-gateway/src crates/exo-gateway/tests
rg -n "multipart|upload|file upload|Content-Type|mime|MIME|body_limit|DefaultBodyLimit" crates/exo-gateway/src crates/exo-gateway/tests
```

## Notes

No production code change was required for this slice because the checked gateway
findings did not reproduce against current `main`. The only remaining non-security
API cleanup noted here is optional response-envelope consistency across every
gateway route; the tested security property is that 5xx and DB-unavailable paths
do not leak raw internal error strings or deployment configuration details.
