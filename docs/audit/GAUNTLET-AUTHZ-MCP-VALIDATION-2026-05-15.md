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

# Gauntlet Authz and MCP Current-Main Validation - 2026-05-15

This record preserves current-main verification for selected Wally Fipps
Gauntlet findings in the authentication, authorization, GraphQL mutation, REST,
MCP authority, and MCP prompt-injection cluster.

The source artifacts remain imported evidence and were not committed as source
files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `28e8e8c7cba64633b8de31b39af7bc1701801c73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gateway/src/graphql.rs` | Core runtime adapter | GraphQL schema and resolver surface for governance reads and disabled mutation paths. |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | REST routing, session authentication, tenant scoping, dashboard persistence, and feedback endpoints. |
| `crates/exo-gateway/src/auth.rs` | Core runtime adapter | DID signature and credential verification primitives used by gateway request authentication. |
| `crates/exo-node/src/mcp/middleware.rs` | Core runtime adapter | MCP tool-call constitutional enforcement boundary. |
| `crates/exo-node/src/mcp/prompts/` | Core runtime adapter | MCP prompt templates that package caller-supplied data for agents. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-001 GraphQL mutations execute without caller authentication | Stale / already remediated | `guard_graphql_mutation_execution()` rejects every mutation, including with `unaudited-gateway-graphql-api` enabled, until a verified authenticated actor and constitutional adjudication context are wired. |
| F-002 REST endpoints have no role/auth check | Stale / already remediated for the reported owned routes | Sensitive REST reads, tenant-scoped resources, dashboard layout persistence, and feedback issue routes require DB-backed bearer sessions before DB/state reads or writes. Registration/enrollment are proof-bearing DID document registration paths, not authority grants. |
| F-004 Login issues a session token without signature verification | Stale / already remediated | `handle_auth_login` calls `authenticate_session_login_with_state` before token generation; session-login proofs bind DID, session metadata, HLC timestamp, and Ed25519 signature over a canonical gateway envelope. |
| F-005 MCP middleware hardcodes a valid authority chain | Stale / already remediated | MCP tool calls require caller-supplied `constitutional_context`; middleware verifies signed authority and provenance, binds action hash to tool name and arguments, and fails closed without a configured authority signer. |
| F-007 `auth/me` trusts caller-supplied `X-Actor-Did` | Stale / already remediated | `handle_auth_me` resolves actor DID exclusively from the bearer session token; source guards reject reliance on `x-actor-did`. |
| F-008 `advance_decision` accepts arbitrary status | Stale / currently unreachable | GraphQL mutations fail closed before state mutation. The reported resolver body is not reachable through the current executable mutation gate. |
| F-009 `grant_delegation` has no scope verification | Stale / currently unreachable | GraphQL mutations fail closed before delegation writes. The reported resolver body is not reachable through the current executable mutation gate. |
| F-158 MCP prompts inject caller arguments directly into LLM instruction context | Stale / already remediated | All MCP prompt templates package caller arguments inside canonical `BEGIN_UNTRUSTED_USER_ARGUMENTS` / `END_UNTRUSTED_USER_ARGUMENTS` markers and JSON-escape embedded text. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-gateway all_graphql_mutations_refuse_without_verified_authz_context --features unaudited-gateway-graphql-api -- --nocapture
cargo test -p exo-gateway dashboard_persistence_routes_reject_missing_bearer_before_db -- --nocapture
cargo test -p exo-gateway auth_login_handler_requires_proof_of_possession -- --nocapture
cargo test -p exo-gateway auth_me_handler_uses_session_actor_not_x_actor_did -- --nocapture
cargo test -p exo-gateway session_login_authentication_rejects_wrong_key_signature -- --nocapture
cargo test -p exo-gateway graphql_mutation_resolvers_fail_closed_before_state_mutation -- --nocapture
cargo test -p exo-gateway sensitive_read_handlers_require_session_before_state_reads -- --nocapture
cargo test -p exo-gateway auth_me_x_actor_did_header_without_session_is_rejected -- --nocapture
cargo test -p exo-node middleware_refuses_without_verified_invocation_context -- --nocapture
cargo test -p exo-node production_source_does_not_fabricate_mcp_context -- --nocapture
cargo test -p exo-node prompt_get_quarantines_untrusted_arguments_for_all_templates -- --nocapture
```

## Next Triage Targets

Continue with live-current verification before edits:

- Remaining core cryptographic verification and proof-stub findings that still
  map to current owned paths.
- Adjacent CommandBase/crosschecked.ai/livesafe.ai findings only after each
  surface has an intake record and is kept isolated from EXOCHAIN core claims.
