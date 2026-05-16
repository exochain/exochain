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

# Codex Security Findings Triage - 2026-05-16

Imported evidence:
`/Users/bobstewart/Downloads/codex-security-findings-2026-05-16T13-25-31.366Z.csv`

The CSV is external imported evidence and is not source-of-truth code. Each row
below is treated as an untrusted hypothesis until reproduced against current
`main`. Remediation must follow the EXOCHAIN core-first workflow: classify the
affected paths, write a failing regression or bounded source guard, make the
smallest owned enforcement change, run focused and relevant workspace gates,
then isolate the commit and PR from adjacent-surface work.

Current baseline when this triage was created:

- `main` fast-forwarded through `d0cd390a`.
- Source evidence contains 22 high-severity findings, all marked `new`.
- The raw CSV remains outside the repository.
- Pre-existing untracked `docs/heartfield/HEARTFIELD_AI_WHITEPAPER.md` remains
  unrelated to this triage.

## Priority Order

| Priority | Finding | Classification | Current status | First verification target |
|---|---|---|---|---|
| P0 | Session expiry uses deterministic HLC in production | Core runtime adapter: `crates/exo-gateway/src/server.rs`; EXOCHAIN core support: `crates/exo-core/src/hlc.rs` | Next remediation target | Prove expired gateway sessions fail closed under production `AppState::new` |
| P0 | Bearer session TTL uses deterministic counter | Core runtime adapter: `crates/exo-node/src/zerodentity/api.rs`, `crates/exo-node/src/main.rs`; EXOCHAIN core support: `crates/exo-node/src/zerodentity/*`, `crates/exo-core/src/hlc.rs` | Queued after gateway session expiry | Prove retained 0dentity bearer tokens expire by real deployment time, not request count |
| P1 | Client-supplied authority accepted for settlements | EXOCHAIN core: `crates/exo-economy/src/settlement.rs`, `crates/exo-economy/src/value_contribution.rs`; core runtime adapter: `crates/exo-node/src/economy.rs` | Queued | Prove settlement authority cannot be supplied solely by the caller |
| P1 | Vote conflict checks trust caller-supplied affected DIDs | Core runtime adapter: `crates/exo-gateway/src/handlers.rs`; EXOCHAIN core: `crates/exo-governance/src/conflict.rs` | Queued | Prove vote conflict adjudication derives affected parties from owned decision state |
| P1 | MCP trusts unsigned consent and override context | Core runtime adapter: `crates/exo-node/src/mcp/tools/authority.rs`, `crates/exo-node/src/mcp/middleware.rs` | Queued | Prove MCP authority tools reject unsigned or caller-fabricated consent and override context |
| P1 | Quorum counts unproven non-human votes as authentic | EXOCHAIN core: `crates/exo-gatekeeper/src/types.rs`, `crates/exo-gatekeeper/src/invariants.rs`; core runtime adapter: `crates/exochain-wasm/src/gatekeeper_bindings.rs` | Queued | Prove quorum vote provenance is verified for every counted voter class |
| P1 | AVC validation trusts caller approval flag | EXOCHAIN core: `crates/exo-avc/src/credential.rs`, `crates/exo-avc/src/validation.rs` | Queued | Prove human approval evidence is cryptographically bound, not a caller boolean |
| P1 | Single validator can mint arbitrary audit receipts | Core runtime adapter: `crates/exo-node/src/reactor.rs` | Queued | Prove audit receipts are bound to quorum, chain state, and trusted validator membership |
| P1 | Passport API reports active standing without verification | Core runtime adapter: `crates/exo-node/src/passport.rs`, `crates/exo-node/src/main.rs` | Queued | Prove passport active standing is registry-backed and not structurally inferred |
| P2 | WASM receipt verifier trusts caller-supplied actor keys | Core runtime adapter: `crates/exochain-wasm/src/catapult_bindings.rs`; EXOCHAIN core: `crates/exo-catapult/src/receipt.rs` | Queued | Prove WASM receipt verification cannot accept caller-minted DID key bindings |
| P2 | WASM governance trusts caller-supplied keys and roles | Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`, `crates/exochain-wasm/src/governance_bindings.rs`; EXOCHAIN core: `crates/exo-governance/src/deliberation.rs` | Queued | Prove governance close/count paths use trusted key and role resolution |
| P2 | Bailment acceptance trusts caller-supplied bailee key | EXOCHAIN core: `crates/exo-consent/src/bailment.rs`, `crates/exo-consent/src/gatekeeper.rs`; core runtime adapter: `crates/exochain-wasm/src/consent_bindings.rs` | Queued | Prove bailee key is resolved from trusted DID state before acceptance |
| P2 | WASM authority verification skips chain topology validation | Core runtime adapter: `crates/exochain-wasm/src/authority_bindings.rs`; EXOCHAIN core: `crates/exo-authority/src/chain.rs` | Queued | Prove WASM authority-chain verification rejects broken topology and caller-only key maps |
| P2 | WASM decision transitions can disable all invariants | Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`, `packages/exochain-wasm/test/bridge_verification.mjs`; EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs` | Queued | Prove transition exports cannot accept an empty or caller-weakened invariant set |
| P2 | Governance attestations trust caller-supplied keys | Adjacent surface: `demo/services/audit-api/src/index.js`; core runtime adapter: `crates/exochain-wasm/src/gatekeeper_bindings.rs` | Queued behind core-owned runtime issues | Prove governance health attestation keys are pinned or registry-resolved before persistence |
| P2 | Plaintext hashes leak encrypted message contents | EXOCHAIN core: `crates/exo-messaging/src/envelope.rs`, `crates/exo-messaging/src/compose.rs`, `crates/exo-messaging/src/open.rs` | Queued | Prove encrypted-envelope metadata cannot be used as a plaintext equality oracle |
| P2 | Identity erasure deletes third-party conflict records | Core runtime adapter: `crates/exo-gateway/src/server.rs`, `crates/exo-gateway/src/db.rs`, `crates/exo-gateway/src/handlers.rs` | Queued | Prove identity erasure tombstones subject-owned data without deleting independent conflict records |
| P2 | Unbounded DB DID registration enables storage DoS | Core runtime adapter: `crates/exo-gateway/src/server.rs`, `crates/exo-gateway/src/db.rs`, `crates/exo-gateway/migrations/20260504000003_create_did_documents.sql`; EXOCHAIN core: `crates/exo-identity/src/registry.rs` | Queued | Prove tenant-scoped DID registration has durable quota or admission control |
| P2 | Gateway rate limit collapses clients behind proxies | Core runtime adapter: `crates/exo-gateway/src/server.rs` | Queued | Prove rate limiting uses a trusted deployment identity and avoids spoofed forwarded headers |
| P2 | Conflict recusal checks are capped at 1000 declarations | Core runtime adapter: `crates/exo-gateway/src/db.rs`, `crates/exo-gateway/src/server.rs`, `crates/exo-gateway/src/handlers.rs`; EXOCHAIN core: `crates/exo-governance/src/conflict.rs` | Queued | Prove conflict checks are complete or fail closed when the declaration set exceeds bounded read limits |
| P2 | P2P rate limiter slot cap can be permanently exhausted | EXOCHAIN core: `crates/exo-api/src/p2p.rs`; core runtime adapter: `crates/exo-node/src/network.rs` | Queued | Prove stale or abusive P2P limiter slots are evicted deterministically |
| P3 | Untrusted ExoForge issues can drive unapproved code changes | Adjacent workflow surface: `archon/workflows/*`, `archon/commands/*` | Queued after core/runtime issues | Prove issue/workflow prose is bounded as untrusted input before authorizing code, GitHub, or merge operations |

## Tracking Notes

- Findings that mention `demo/`, `site/`, `archon/`, or other non-Rust product
  shells remain adjacent unless a tested runtime adapter proves they can read,
  write, or assert EXOCHAIN core decisions.
- WASM findings are classified as core runtime adapter issues when the export
  can carry consent, authority, provenance, governance, or settlement decisions
  across an untrusted caller boundary.
- Session expiry findings are first because they can invalidate authentication
  and owner-only identity access controls across live runtime adapters.
