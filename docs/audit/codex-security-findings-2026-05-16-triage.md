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
| P0 | Session expiry uses deterministic HLC in production | Core runtime adapter: `crates/exo-gateway/src/server.rs`; EXOCHAIN core support: `crates/exo-core/src/hlc.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-gateway production_app_state_uses_database_time_for_db_backed_session_expiry -- --nocapture`; `cargo test -p exo-gateway production_session_auth_rejects_epoch_expired_token -- --nocapture` |
| P0 | Bearer session TTL uses deterministic counter | Core runtime adapter: `crates/exo-node/src/zerodentity/api.rs`, `crates/exo-node/src/main.rs`; EXOCHAIN core support: `crates/exo-node/src/zerodentity/*`, `crates/exo-core/src/hlc.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-node production_api_state -- --nocapture`; `cargo test -p exo-node store_session -- --nocapture` |
| P1 | Client-supplied authority accepted for settlements | EXOCHAIN core: `crates/exo-economy/src/settlement.rs`, `crates/exo-economy/src/value_contribution.rs`; core runtime adapter: `crates/exo-node/src/economy.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-node automated_settlement_rejects_client_supplied_preconditions -- --nocapture`; `cargo test -p exo-economy automated_settlement_rejects_authority_proof_not_bound_to_adoption -- --nocapture` |
| P1 | Vote conflict checks trust caller-supplied affected DIDs | Core runtime adapter: `crates/exo-gateway/src/handlers.rs`; EXOCHAIN core: `crates/exo-governance/src/conflict.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-gateway trusted_decision_affected_dids_block_conflict_even_when_request_context_is_unrelated -- --nocapture`; `cargo test -p exo-gateway vote_handler_derives_conflict_context_from_locked_decision_state -- --nocapture` |
| P1 | MCP trusts unsigned consent and override context | Core runtime adapter: `crates/exo-node/src/mcp/tools/authority.rs`, `crates/exo-node/src/mcp/middleware.rs`; EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-node middleware_rejects_context_without_context_evidence_signature -- --nocapture`; `cargo test -p exo-node execute_check_consent_refuses_without_live_registry -- --nocapture` |
| P1 | Quorum counts unproven non-human votes as authentic | EXOCHAIN core: `crates/exo-gatekeeper/src/types.rs`, `crates/exo-gatekeeper/src/invariants.rs`; core runtime adapter: `crates/exochain-wasm/src/gatekeeper_bindings.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-gatekeeper quorum_rejects_raw_votes_without_verified_vote_provenance -- --nocapture`; `cargo test -p exochain-wasm wasm_enforce_invariants_rejects_unproven_caller_quorum_evidence -- --nocapture` |
| P1 | AVC validation trusts caller approval flag | EXOCHAIN core: `crates/exo-avc/src/credential.rs`, `crates/exo-avc/src/validation.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-avc risk_above_threshold_ignores_caller_approval_flag -- --nocapture`; `cargo test -p exo-avc human_approval_signature_binds_action_fields -- --nocapture` |
| P1 | Single validator can mint arbitrary audit receipts | Core runtime adapter: `crates/exo-node/src/reactor.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-node inbound_governance_audit_event_cannot_mint_receipt_without_commit_certificate -- --nocapture`; `cargo test -p exo-node local_commit_persists_certificate_receipt_and_emits_event -- --nocapture` |
| P1 | Passport API reports active standing without verification | Core runtime adapter: `crates/exo-node/src/passport.rs`, `crates/exo-node/src/main.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-node passport_active_standing_requires_verified_claim_evidence -- --nocapture`; `cargo test -p exo-node passport_known_validator_without_verified_claims_is_not_active -- --nocapture` |
| P2 | WASM receipt verifier trusts caller-supplied actor keys | Core runtime adapter: `crates/exochain-wasm/src/catapult_bindings.rs`; EXOCHAIN core: `crates/exo-catapult/src/receipt.rs` | Verified remediated on current main; no code change required | `cargo test -p exochain-wasm receipt_chain_export_rejects_caller_supplied_actor_key_binding -- --nocapture`; `cargo test -p exo-catapult signed_chain_verification_rejects_missing_actor_key -- --nocapture` |
| P2 | WASM governance trusts caller-supplied keys and roles | Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`, `crates/exochain-wasm/src/governance_bindings.rs`; EXOCHAIN core: `crates/exo-governance/src/deliberation.rs` | Verified remediated on current main; no code change required | `cargo test -p exochain-wasm wasm_governance_verified_paths_reject_caller_supplied_keys_and_roles -- --nocapture`; `cargo test -p exo-governance close_verified_rejects_forged_vote_signature -- --nocapture` |
| P2 | Bailment acceptance trusts caller-supplied bailee key | EXOCHAIN core: `crates/exo-consent/src/bailment.rs`, `crates/exo-consent/src/gatekeeper.rs`; core runtime adapter: `crates/exochain-wasm/src/consent_bindings.rs` | Verified remediated on current main; no code change required | `cargo test -p exo-consent accept_rejects_caller_substituted_bailee_key -- --nocapture`; `cargo test -p exochain-wasm wasm_accept_bailment_rejects_caller_supplied_bailee_key_material -- --nocapture` |
| P2 | WASM authority verification skips chain topology validation | Core runtime adapter: `crates/exochain-wasm/src/authority_bindings.rs`; EXOCHAIN core: `crates/exo-authority/src/chain.rs` | Queued | Prove WASM authority-chain verification rejects broken topology and caller-only key maps |
| P2 | WASM decision transitions can disable all invariants | Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`, `packages/exochain-wasm/test/bridge_verification.mjs`; EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs` | Verified remediated on current main; no code change required | `cargo test -p exochain-wasm wasm_decision_transition_requires_kernel_adjudication -- --nocapture`; `node packages/exochain-wasm/test/bridge_verification.mjs` |
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

## Verification Log

### P0 - Session Expiry Uses Deterministic HLC In Production

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-gateway/src/server.rs`.
- EXOCHAIN core support: `crates/exo-core/src/hlc.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Production `AppState::new` constructs DB-backed gateway state with
  `SessionTimeSource::DatabaseWhenAvailable`.
- `trusted_session_validation_time_ms` uses `trusted_database_epoch_ms` when a
  DB pool is present, falling back to HLC only for injected-clock/dev paths.
- `require_authenticated_session_actor_for_token` queries
  `sessions` with `expires_at > trusted_session_validation_time_ms(state)`.
- Session validation source guards prove caller-supplied observed-at headers do
  not drive DB-backed session expiry checks.

Validation commands:

```bash
cargo test -p exo-gateway production_app_state_uses_database_time_for_db_backed_session_expiry -- --nocapture
cargo test -p exo-gateway session_validation_uses_gateway_clock_not_caller_header_time -- --nocapture
cargo test -p exo-gateway production_session_auth_rejects_epoch_expired_token -- --nocapture
```

### P0 - Bearer Session TTL Uses Deterministic Counter

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-node/src/zerodentity/api.rs` and
  `crates/exo-node/src/main.rs`.
- EXOCHAIN core support: `crates/exo-node/src/zerodentity/*` and
  `crates/exo-core/src/hlc.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Production `ApiState::new` does not install `HybridClock::new()` or any
  deterministic session clock.
- Production 0dentity session-protected routes fail closed with
  `Trusted 0dentity session clock unavailable` unless a trusted clock is
  explicitly injected by `new_with_clock`.
- `ZerodentityStore::get_session` rejects revoked sessions, expired sessions,
  future-created sessions, and expiry-deadline arithmetic overflow.
- API-level session reads reject retained bearer tokens once the absolute
  24-hour `IDENTITY_SESSION_TTL_MS` deadline is reached.

Validation commands:

```bash
cargo test -p exo-node production_api_state -- --nocapture
cargo test -p exo-node list_claims_rejects_expired_session -- --nocapture
cargo test -p exo-node store_session -- --nocapture
```

### P1 - Client-Supplied Authority Accepted For Settlements

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- EXOCHAIN core: `crates/exo-economy/src/settlement.rs` and
  `crates/exo-economy/src/value_contribution.rs`.
- Core runtime adapter: `crates/exo-node/src/economy.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- The node economy API rejects client-supplied automated-settlement
  preconditions instead of trusting request-provided `authority_valid` flags.
- Runtime automated settlement derives preconditions from stored offer,
  acceptance, adoption, contribution-node, wrapper, ruleset, and value-event
  records.
- Request `automation_authority_ref` must match the stored contribution
  acceptance authority envelope and adoption proof hash.
- Core settlement preconditions fail closed when delegated authority is invalid
  or a dispute is active.

Validation commands:

```bash
cargo test -p exo-node automated_settlement_rejects_client_supplied_preconditions -- --nocapture
cargo test -p exo-node automated_settlement_rejects_request_authority_not_bound_to_stored_acceptance -- --nocapture
cargo test -p exo-economy automated_settlement_rejects_authority_proof_not_bound_to_adoption -- --nocapture
cargo test -p exo-economy automated_preconditions_fail_closed_for_missing_authority_and_active_dispute -- --nocapture
```

### P1 - Vote Conflict Checks Trust Caller-Supplied Affected DIDs

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-gateway/src/handlers.rs`.
- EXOCHAIN core: `crates/exo-governance/src/conflict.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- The vote handler loads the stored `DecisionObject` under a row lock and
  derives conflict `affected_dids` from the decision's trusted metadata.
- Request-body `affected_dids` can no longer make conflict adjudication
  unrelated or empty.
- Conflict recusal uses `load_blocking_conflict_declarations_for_vote` with
  trusted affected DIDs and fails closed when the trusted context is empty.
- `check_and_block` remains the enforcing gate before kernel adjudication and
  vote persistence.

Validation commands:

```bash
cargo test -p exo-gateway trusted_decision_affected_dids_block_conflict_even_when_request_context_is_unrelated -- --nocapture
cargo test -p exo-gateway vote_handler_derives_conflict_context_from_locked_decision_state -- --nocapture
cargo test -p exo-gateway vote_handler_source_does_not_default_conflict_adjudication -- --nocapture
cargo test -p exo-gateway conflict_declaration_loader_rejects_empty_recusal_context -- --nocapture
```

### P1 - MCP Trusts Unsigned Consent And Override Context

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-node/src/mcp/middleware.rs`,
  `crates/exo-node/src/mcp/tools/authority.rs`, and
  `crates/exo-node/src/mcp/tools/consent.rs`.
- EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- `ConstitutionalMiddleware::new()` has no MCP authority and fails closed until
  a configured authority is supplied through `with_authority`.
- Tool calls must include top-level `constitutional_context`; the middleware
  parses the nested adjudication context with trusted authority and provenance
  key maps and refuses absent, unsigned, replayed, or tampered context.
- `context_evidence` is domain-separated, signed over the full adjudication
  context, bound to the actor DID, and verified against trusted provenance
  keys before MCP facts are derived.
- The middleware binds provenance `action_hash` to the tool name and arguments,
  so a signed context cannot be replayed against a different MCP action or
  argument set.
- Consent is derived from active bailment and consent records inside the
  verified adjudication context, not from a caller boolean.
- Consent read and mutation tools refuse by default when no live consent
  registry or signed store is attached; the `unaudited-mcp-simulation-tools`
  feature does not enable fabricated consent reads or writes.

Validation commands:

```bash
cargo test -p exo-node middleware_rejects_signed_context_replayed_with_different_arguments -- --nocapture
cargo test -p exo-node middleware_rejects_context_without_context_evidence_signature -- --nocapture
cargo test -p exo-node middleware_rejects_adjudication_context_tampering_after_signing -- --nocapture
cargo test -p exo-node middleware_refuses_without_verified_invocation_context -- --nocapture
cargo test -p exo-node production_source_does_not_fabricate_mcp_context -- --nocapture
cargo test -p exo-node execute_adjudicate_action_requires_verified_context -- --nocapture
cargo test -p exo-node execute_check_consent_refuses_without_live_registry -- --nocapture
cargo test -p exo-node execute_propose_bailment_refuses_by_default -- --nocapture
```

### P1 - Quorum Counts Unproven Non-Human Votes As Authentic

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs` and
  `crates/exo-gatekeeper/src/types.rs`.
- Core runtime adapter: `crates/exochain-wasm/src/gatekeeper_bindings.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- `check_quorum_legitimate` counts `verified_human_quorum_approvals`, not raw
  approval count, when enforcing `ConstitutionalInvariant::QuorumLegitimate`.
- Each counted quorum vote must carry provenance whose actor matches the voter,
  whose voice kind is human, whose independence claim is independent, and whose
  review order is first-order.
- The voter provenance public key must be present in
  `trusted_provenance_keys`, bound to the voter DID, and used to verify the
  provenance signature.
- The vote's approval decision has its own domain-separated signature
  (`quorum_vote_signature_message`) verified with the same DID-bound key, so
  tampering with the approval flag after signing fails closed.
- Legacy votes with no provenance, synthetic votes, coordinated/derivative
  votes, actor/voter mismatches, and unsigned vote decisions are rejected from
  the threshold count.
- The public WASM invariant boundary rejects unproven caller-supplied quorum
  evidence and does not accept caller-supplied trusted provenance keys as an
  authority source.

Validation commands:

```bash
cargo test -p exo-gatekeeper quorum_rejects_raw_votes_without_verified_vote_provenance -- --nocapture
cargo test -p exo-gatekeeper quorum_fails_when_synthetic_makes_up_threshold -- --nocapture
cargo test -p exo-gatekeeper quorum_passes_when_humans_meet_threshold_despite_synthetics -- --nocapture
cargo test -p exo-gatekeeper quorum_rejects_legacy_votes_no_provenance -- --nocapture
cargo test -p exo-gatekeeper quorum_rejects_non_human_or_non_independent_vote_provenance -- --nocapture
cargo test -p exo-gatekeeper quorum_rejects_tampered_human_voice_metadata_after_signing -- --nocapture
cargo test -p exo-gatekeeper quorum_rejects_unsigned_vote_decision_with_valid_human_provenance -- --nocapture
cargo test -p exo-gatekeeper quorum_rejects_approval_flag_tampering_after_vote_signing -- --nocapture
cargo test -p exo-gatekeeper quorum_is_met_authentic -- --nocapture
cargo test -p exochain-wasm wasm_enforce_invariants_rejects_unproven_caller_quorum_evidence -- --nocapture
```

### P1 - AVC Validation Trusts Caller Approval Flag

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- EXOCHAIN core: `crates/exo-avc/src/credential.rs` and
  `crates/exo-avc/src/validation.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- `AvcActionRequest::requires_human_approval` is not used as proof of approval.
- `human_approval_signature_payload` explicitly excludes the caller-provided
  approval flag and signs the credential ID, action ID, actor DID, requested
  permission, tool, target DID, data class, budget estimate, risk estimate,
  action name, approver DID, approval time, and expiry.
- `enforce_risk` derives the need for approval from credential constraints and
  risk threshold, not from the caller flag.
- `verify_human_approval` requires a non-empty approval signature, rejects
  future, expired, or malformed approval windows, resolves the approver key
  through `resolve_human_approval_key`, and verifies the domain-separated
  approval payload before allowing the action.
- Optional human approval evidence is still verified when present, so a caller
  cannot attach invalid approval data to bypass or launder a validation result.

Validation commands:

```bash
cargo test -p exo-avc risk_above_threshold_ignores_caller_approval_flag -- --nocapture
cargo test -p exo-avc credential_human_approval_required_blocks_action_without_evidence -- --nocapture
cargo test -p exo-avc signed_human_approval_satisfies_credential_requirement -- --nocapture
cargo test -p exo-avc signed_human_approval_satisfies_risk_threshold -- --nocapture
cargo test -p exo-avc human_approval_from_untrusted_approver_is_invalid -- --nocapture
cargo test -p exo-avc issuer_public_key_alone_does_not_authorize_human_approval -- --nocapture
cargo test -p exo-avc optional_human_approval_evidence_must_still_verify -- --nocapture
cargo test -p exo-avc human_approval_signature_binds_action_fields -- --nocapture
cargo test -p exo-avc human_approval_with_empty_signature_is_invalid -- --nocapture
cargo test -p exo-avc expired_human_approval_is_rejected -- --nocapture
```

### P1 - Single Validator Can Mint Arbitrary Audit Receipts

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-node/src/reactor.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Governance audit events are signature-verified against the validator public
  key resolver, schema-validated, and emitted as reactor events without calling
  `TrustReceipt::new` or persisting trust receipts.
- Single-validator no-peer fallback applies audit events locally but does not
  mint durable receipts.
- Commit receipts are built only from `CommitCertificate` evidence through
  `commit_receipt_from_certificate`.
- The receipt authority hash is a domain-separated canonical hash over the full
  commit certificate, binding the receipt to quorum votes, validator
  membership, round, and committed node hash.
- Receipt timestamps are loaded from the committed DAG node, not local wall
  clock state.
- Local and network commit paths verify the certificate against the current
  validator public-key resolver and persist commit state and receipt atomically
  before advancing live consensus state.

Validation commands:

```bash
cargo test -p exo-node governance_audit_apply_path_does_not_persist_receipts -- --nocapture
cargo test -p exo-node commit_receipt_uses_certificate_authority_and_node_timestamp -- --nocapture
cargo test -p exo-node single_validator_no_peers_applies_audit_event_without_minting_receipt -- --nocapture
cargo test -p exo-node inbound_governance_audit_event_emits_without_minting_receipt -- --nocapture
cargo test -p exo-node inbound_governance_audit_event_cannot_mint_receipt_without_commit_certificate -- --nocapture
cargo test -p exo-node single_validator_fallback_cannot_mint_audit_receipt_without_commit_certificate -- --nocapture
cargo test -p exo-node inbound_governance_audit_event_rejects_bad_signature -- --nocapture
cargo test -p exo-node commit_receipt_timestamp_rejects_missing_node -- --nocapture
cargo test -p exo-node local_commit_does_not_advance_without_persisted_trust_receipt -- --nocapture
cargo test -p exo-node network_commit_does_not_advance_without_persisted_trust_receipt -- --nocapture
cargo test -p exo-node local_commit_persists_certificate_receipt_and_emits_event -- --nocapture
```

### P1 - Passport API Reports Active Standing Without Verification

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exo-node/src/passport.rs` and
  `crates/exo-node/src/main.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- `build_standing_profile` loads 0dentity claims from the trusted
  `ZerodentityStore` and fails closed if claim retrieval is unavailable.
- Standing status becomes `active` only through `has_active_verified_claim`,
  which requires at least one stored claim with `ClaimStatus::Verified`.
- Known validator membership alone does not confer active standing; a known
  validator without verified claims remains `unknown`.
- Unrecognized DIDs remain `unknown`, and unavailable trust sources are marked
  unavailable instead of fabricating active standing or counts.
- Source guards assert the standing profile does not use
  `.unwrap_or_default()` and does not infer active standing from
  `known || !claims.is_empty()`.

Validation commands:

```bash
cargo test -p exo-node passport_active_standing_requires_verified_claim_evidence -- --nocapture
cargo test -p exo-node passport_known_validator_without_verified_claims_is_not_active -- --nocapture
cargo test -p exo-node standing_shows_active_for_validator_with_verified_claim -- --nocapture
cargo test -p exo-node standing_shows_unknown_for_unrecognized_did -- --nocapture
cargo test -p exo-node passport_returns_profile_for_known_validator -- --nocapture
cargo test -p exo-node standing_fails_closed_when_claim_read_fails -- --nocapture
cargo test -p exo-node passport_marks_unavailable_trust_sources_without_fabricated_counts -- --nocapture
```

### P2 - WASM Receipt Verifier Trusts Caller-Supplied Actor Keys

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exochain-wasm/src/catapult_bindings.rs`.
- EXOCHAIN core: `crates/exo-catapult/src/receipt.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Public WASM `wasm_verify_franchise_receipt_chain` fails closed and requires a
  trusted core runtime adapter with registry-backed actor DID resolution.
- Public WASM `wasm_verify_franchise_receipt_chain_with_keys` rejects
  caller-supplied actor public-key registries instead of authenticating DID
  bindings supplied by the caller.
- The WASM production section does not call hash-only
  `ReceiptChain::verify_chain()` and does not contain a
  `parse_actor_public_key_registry` path.
- Core `ReceiptChain::verify_signed_chain` verifies hash linkage and every
  receipt signature through a trusted `Did -> PublicKey` resolver.
- Missing actor keys fail closed with `InvalidReceipt`, and tampered signatures
  are rejected after deserialization even when hash linkage remains intact.

Validation commands:

```bash
cargo test -p exochain-wasm receipt_chain_export_requires_actor_key_verification -- --nocapture
cargo test -p exochain-wasm receipt_chain_export_rejects_caller_supplied_actor_key_binding -- --nocapture
cargo test -p exo-catapult signed_chain_verification_rejects_signature_tamper_after_deserialize -- --nocapture
cargo test -p exo-catapult signed_chain_verification_rejects_missing_actor_key -- --nocapture
cargo test -p exo-catapult chain_append_requires_valid_signature_and_prev_hash -- --nocapture
```

### P2 - WASM Governance Trusts Caller-Supplied Keys And Roles

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`
  and `crates/exochain-wasm/src/governance_bindings.rs`.
- EXOCHAIN core: `crates/exo-governance/src/deliberation.rs` and
  `crates/exo-governance/src/quorum.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Public WASM `wasm_compute_quorum` and `wasm_close_deliberation` fail closed
  and refuse caller-supplied signer keys or voter roles.
- Public WASM constitution ratification and amendment exports fail closed and
  refuse caller-supplied signer keys or eligible signer sets.
- WASM source guards prove public exports do not parse caller-supplied DID key
  bindings and do not call verified quorum or close paths with a
  caller-controlled resolver.
- Core production deliberation closure uses `close_verified`; the structural
  `close` helper is test-only.
- `close_verified` scopes vote signatures to the deliberation id, proposal
  hash, position, and reasoning hash before calling verified quorum logic.
- `compute_quorum_verified` requires trusted `PublicKeyResolver` output;
  unresolved DIDs, duplicate approvers, and invalid signatures do not count.

Validation commands:

```bash
cargo test -p exochain-wasm wasm_governance_verified_paths_reject_caller_supplied_keys_and_roles -- --nocapture
cargo test -p exochain-wasm wasm_constitution_exports_reject_caller_supplied_signer_keys -- --nocapture
cargo test -p exo-governance production_deliberation_closure_uses_verified_quorum_only -- --nocapture
cargo test -p exo-governance close_verified_rejects_forged_vote_signature -- --nocapture
cargo test -p exo-governance close_without_resolver_fails_closed_for_unverified_quorum -- --nocapture
cargo test -p exo-governance close_verified_rejects_vote_signature_replayed_to_other_deliberation -- --nocapture
cargo test -p exo-governance close_verified_rejects_vote_signature_replayed_to_other_position -- --nocapture
cargo test -p exo-governance close_verified_rejects_vote_signature_replayed_to_other_reasoning_hash -- --nocapture
cargo test -p exo-governance compute_quorum_verified_requires_valid_approval_signature -- --nocapture
cargo test -p exo-governance compute_quorum_verified_unresolved_did_not_counted -- --nocapture
```

### P2 - Bailment Acceptance Trusts Caller-Supplied Bailee Key

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- EXOCHAIN core: `crates/exo-consent/src/bailment.rs` and
  `crates/exo-consent/src/gatekeeper.rs`.
- Core runtime adapter: `crates/exochain-wasm/src/consent_bindings.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- Core `bailment::accept` requires callers to supply a trusted resolver for
  `bailment.bailee_did` and verifies the bailee signature against the resolved
  key before the status transition.
- Empty signatures, zero-byte signatures, invalid non-empty signatures,
  wrong-key signatures, unresolved trusted bailee keys, tampered bailments, and
  replayed signatures over different bailment payloads are rejected.
- Successful acceptance stores the resolved bailee public key with the
  signature, and active-bailment checks require the stored proof to continue
  verifying over the canonical acceptance payload.
- `ConsentGate` denies status-forged active bailments that lack a valid
  acceptance proof.
- Public WASM `wasm_accept_bailment` fails closed and instructs callers to use
  `wasm_bailment_signing_payload` plus a trusted core runtime adapter instead
  of trusting caller-supplied DID key material.

Validation commands:

```bash
cargo test -p exo-consent accept_rejects_caller_substituted_bailee_key -- --nocapture
cargo test -p exo-consent accept_rejects_unresolved_bailee_key -- --nocapture
cargo test -p exo-consent accept_rejects_non_empty_but_invalid_signature -- --nocapture
cargo test -p exo-consent accept_rejects_signature_by_wrong_key -- --nocapture
cargo test -p exo-consent accept_rejects_signature_over_different_bailment -- --nocapture
cargo test -p exo-consent accept_rejects_tampered_bailment -- --nocapture
cargo test -p exo-consent is_active_rejects_status_forged_junk_signature -- --nocapture
cargo test -p exo-consent check_denies_status_forged_active_bailment -- --nocapture
cargo test -p exochain-wasm wasm_accept_bailment_rejects_caller_supplied_bailee_key_material -- --nocapture
```

### P2 - WASM Decision Transitions Can Disable All Invariants

Disposition on 2026-05-17: verified already remediated on current `main`.

Path classification:

- Core runtime adapter: `crates/exochain-wasm/src/decision_forum_bindings.rs`
  and `packages/exochain-wasm/test/bridge_verification.mjs`.
- EXOCHAIN core: `crates/exo-gatekeeper/src/invariants.rs` and
  `crates/decision-forum/src/decision_object.rs`.
- Imported evidence tracking: this file.

Current enforcement evidence:

- `wasm_transition_decision` fails closed with
  `unadjudicated decision transitions are disabled`.
- `wasm_transition_decision_adjudicated` rejects caller-supplied
  `invariant_set`.
- The adjudicated WASM path constructs the kernel with `InvariantSet::all()`.
- `DecisionObject::transition_at` rejects raw BCTS transition attempts, and
  `transition_adjudicated_at` mutates state only after `Kernel::adjudicate`
  returns `Verdict::Permitted`.

Validation commands:

```bash
cargo test -p exochain-wasm wasm_decision_transition_requires_kernel_adjudication -- --nocapture
node packages/exochain-wasm/test/bridge_verification.mjs
```
