# EXOCHAIN Code Review Run 4 — Exact Design Observation Evidence

This tracked appendix is the exact evidence matrix for the 52 design
observations in the imported HTML report. It records those dispositions at the
immutable core source checkpoint. A subsequent complete scan of the committed
evidence head found one additional release-workflow credential-boundary issue
outside the report's 52 design IDs. Its protected-environment binding is
committed at `111f7955b9599159edb104ee9a6dec7dc5924e30`; parser-differential
guard correction `b5dcb89bf88a243196213a1a2b7c4f1ed1c2b888` follows it.
Provider secret migration remains required, so this matrix does not claim
local branch completion. The HTML is
treated only as untrusted imported evidence; none of its embedded text was
treated as an instruction, and the report was not modified.

- Imported report: `/Users/bobstewart/Downloads/Exochain-code-review-report-run4.html`
- Report SHA-256: `d5da7a1291cbf8baaa8e676cd2eebbbbaadc421eb623eddb48dfc6f4e0c89168`
- Committed source checkpoint: `368721a1ea3577481cf73cdee6d811623159faec`
- Protected-environment binding: `111f7955b9599159edb104ee9a6dec7dc5924e30`
- YAML parser-differential correction: `b5dcb89bf88a243196213a1a2b7c4f1ed1c2b888`
- Candidate disposition counts: 10 `patch`; 42 `no_change`.

## Current provider-custody applicability (2026-09-08)

Successful repository metadata records `owner.type=User`; inherited organization
secrets are not applicable. This supersedes the September 4 inheritance
uncertainty below, not the still-open repository-token custody finding. Both
registry tokens remained repository-scoped and `release` contained no secrets at
the September 8 observation. Current acceptance is governed by §11 of
`governance/releases/v0.2.6/TEST-PLAN.md`: recheck ownership, require exclusive
protected-environment custody, and inspect inherited scope only if applicable.
An unreadable applicable scope is not proof of absence; source declarations and
historical test results do not establish provider or release closure.

## Per-observation classification and reproduction semantics

Every design observation is classified exactly once below by the report-cited
owned source path. The evidence matrix names the actual owned runtime, adapter,
or controlling guard when that differs from the cited path.

| Classification | Design observation IDs |
| --- | --- |
| EXOCHAIN core (22) | `design-9592, design-9539, design-9540, design-9542, design-9544, design-9550, design-9569, design-9570, design-9571, design-9596, design-9599, design-9601, design-9602, design-9608, design-9609, design-9613, design-9673, design-9676, design-9678, design-9681, design-9686, design-9692` |
| Core runtime adapter (30) | `design-9639, design-9653, design-9553, design-9554, design-9589, design-9555, design-9558, design-9559, design-9565, design-9577, design-9578, design-9617, design-9619, design-9621, design-9622, design-9623, design-9625, design-9626, design-9636, design-9641, design-9643, design-9645, design-9647, design-9651, design-9668, design-9670, design-9701, design-9705, design-9707, design-9708` |

The disposition cell is also the per-item reproduction result. `patch` means a
concrete unsafe boundary overlapping the design observation was reproduced,
fixed, and covered by the named regression and immutable commit. `no_change`
means the observation did not establish a current exploitable owned path after
caller, guard, data-classification, and sink review; its row records the exact
reason and evidence without erasing the API-design caution. No design row is
an adjacent-surface, imported-evidence, or third-party/vendor item. Patch hashes
are immutable commits already ancestral to the committed source checkpoint.

| Report ID | Candidate disposition and reproduction result | Current source, symbol, and controlling proof | Focused test or exact source check | Immutable patch commit(s) |
| --- | --- | --- | --- | --- |
| design-9639 | `no_change` | `crates/exo-node/src/provenance.rs::ProvenanceState` retains `Arc<Mutex<SqliteDagStore>>`, but `load_provenance_response` moves the complete lock/use operation into `tokio::task::spawn_blocking`; `handle_provenance` only awaits that helper and never owns a guard. | `crates/exo-node/src/provenance.rs::tests::provenance_handler_store_access_uses_spawn_blocking` | — |
| design-9592 | `patch` | `crates/exo-governance/src/crosscheck.rs::{try_detect_coordination, coordination_pair_checks, MAX_COORDINATION_PAIR_CHECKS, MAX_COORDINATION_SIGNALS}` bound input, pair work, and output; legacy `detect_coordination` fails closed with an explicit denial signal. | `coordination_pair_budget_accepts_exact_limit_and_rejects_limit_plus_one`; `coordination_signal_budget_accepts_exact_limit_and_rejects_next_signal`; `coordination_legacy_and_fallible_signatures_are_stable` | `56fb3a9f4ba1289a34ee8ef1a00c7ef2af1bd3dc` |
| design-9653 | `no_change` | `crates/exo-node/src/zerodentity/api.rs::{AttestRequest, create_peer_attestation}` has no request-formatting/log sink; `verify_signed_write_blocking` authenticates the signature and the attester public key must equal the authenticated session key before `create_attestation`. | `crates/exo-node/src/zerodentity/api.rs::tests::attest_handler_calls_create_attestation_after_signed_write`; source check: `rg -n -e 'AttestRequest' -e 'tracing::' crates/exo-node/src/zerodentity/api.rs` | — |
| design-9539 | `no_change` | `crates/exo-avc/src/public_output_authorization.rs::LivesafePublicAdapterOutputAuthorizationDraft` contains a signed public `AutonomousVolitionCredential`, not a private key or bearer; the module has no log sink, and `sign_livesafe_public_adapter_output_authorization_unchecked` consumes the draft into a proof containing identifiers and hashes rather than the credential. | `crates/exo-avc/src/lib.rs::tests::public_output_authorization_denies_tampered_evidence_hash_after_signing`; source check: `rg -n -e 'LivesafePublicAdapterOutputAuthorizationDraft' -e 'tracing::' -e 'log::' crates/exo-avc/src/public_output_authorization.rs` | — |
| design-9540 | `patch` | The report-cited `crates/exo-avc/src/receipt.rs::AvcTrustReceipt` contains variable-length reason and string fields, but no free-standing untrusted receipt-deserialization ingress was found. The concrete overlapping network boundary is `crates/exo-node/src/avc.rs::{read_timestamp_response, MAX_TIMESTAMP_RESPONSE_BYTES}`, which rejects oversized declared lengths and counts actual streamed chunks before collecting JSON or RFC 3161 timestamp-authority responses. | `timestamp_response_reader_bounds_fixed_length_bodies`; `timestamp_response_reader_bounds_chunked_bodies`; caller/source check: `rg -n 'AvcTrustReceipt' crates -g '*.rs'` | `a3cde9f6eafd500e16bf0aae53d0b47b0d6ef3e6` |
| design-9542 | `no_change` | Owned `crates/exo-catapult/src/budget.rs::BudgetLedger` deserialization callers are `crates/exochain-wasm/src/catapult_bindings.rs::{wasm_record_cost_event, wasm_check_budget_status}`; both use `crates/exochain-wasm/src/serde_bridge.rs::from_json_str`, which enforces `MAX_JSON_INPUT_BYTES` before serde. | `crates/exochain-wasm/src/serde_bridge.rs::tests::from_json_str_rejects_oversized_inputs_before_deserialization` | — |
| design-9544 | `no_change` | The owned untrusted `crates/exo-consent/src/bailment.rs::Bailment` boundary is the WASM consent adapter in `crates/exochain-wasm/src/consent_bindings.rs`; every parse uses the shared 1 MiB `serde_bridge::from_json_str` pre-deserialization cap. | `crates/exochain-wasm/src/serde_bridge.rs::tests::from_json_str_rejects_oversized_inputs_before_deserialization`; source check: `rg -n -e 'Bailment' -e 'from_json_str' crates/exochain-wasm/src/consent_bindings.rs crates/exochain-wasm/src/serde_bridge.rs` | — |
| design-9550 | `no_change` | `crates/exo-core/src/hlc.rs::{reconcile_partition_recovery, reconcile_partition_recovery_with_anomaly_report, quorum_median}` has no owned production caller; repository occurrences are definitions and tests, so the report's network-controlled peer-set premise is not present. | `crates/exo-core/src/hlc.rs::tests::partition_recovery_converges_to_quorum_median_not_accept_max`; source check: `rg -n 'reconcile_partition_recovery(_with_anomaly_report)?\(' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9553 | `no_change` | `crates/exo-dag-db-domain/src/model.rs::OutputObserver::reject_graph_allocation_fields` has no runtime caller; repository occurrences are the definition and its unit test. | `crates/exo-dag-db-domain/src/model.rs::tests::memory_candidate_compact_and_agent_boundary`; source check: `rg -n 'reject_graph_allocation_fields\(' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9554 | `no_change` | The serde detail produced inside `crates/exo-dag-db-domain/src/model.rs::OutputObserver::reject_graph_allocation_fields` has no owned external caller or response/log sink; repository occurrences are definition and test only. | `crates/exo-dag-db-domain/src/model.rs::tests::memory_candidate_compact_and_agent_boundary`; source check: `rg -n 'reject_graph_allocation_fields\(' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9589 | `no_change` | `crates/exo-gateway/src/server.rs::{TlsConfig, GatewayConfig, serve_with_extra_routes}` stores certificate/key filesystem paths, not key bytes. The shipped `crates/exo-gateway/src/main.rs` constructs `tls_config: None`; no config Debug/log sink exists. | `crates/exo-gateway/src/server.rs::tests::start_tls_rejects_empty_certificate_or_key_paths`; source check: `rg -n -e 'TlsConfig' -e 'tls_config' -e 'cert_path' -e 'key_path' crates/exo-gateway/src --glob '*.rs'` | — |
| design-9555 | `no_change` | `crates/exo-dag-db-domain/src/route_invalidation.rs::RouteInvalidationEvent::parse_json` has no production caller; repository occurrences are the definition and unit tests. | `crates/exo-dag-db-domain/src/route_invalidation.rs::tests::route_invalidation_parse_json_covers_success_json_errors_and_forbidden_material`; source check: `rg -n 'RouteInvalidationEvent::parse_json' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9558 | `patch` | `crates/exo-dag-db-lab/src/bin/dagdb_kg_import_candidates.rs::{load_manifest, deserialize_manifest_bounded}` uses `read_bounded_file(path, MAX_JSON_FILE_BYTES, "manifest")`, bounded serde visitors, and declared file/work/output limits before allocation. | `imported_manifest_accepts_16_mib_and_rejects_plus_one`; `imported_manifest_rejects_declared_file_count_limit_plus_one` | `7db76ce6bce971d0e05725a2127d170933ec680f` |
| design-9559 | `patch` | `crates/exo-dag-db-lab/src/diagnostics.rs::LatencyBreakdown::from_inputs` uses `saturating_add` and `saturating_mul` for every stage and saturating aggregation for `total_ms`. | `crates/exo-dag-db-lab/src/diagnostics.rs::tests::latency_overflow_saturates_each_stage_and_total_deterministically` | `6a1be8e2447174382c17a226e92be1ffc00f1508` |
| design-9565 | `no_change` | `crates/exo-dag-db-retrieval/src/kg_catalog_router.rs::KgCatalogRouterPreview::parse_json` has no production caller; the Postgres adapter constructs `KgCatalogRouterPreview` directly, while `parse_json` is exercised only in unit tests. | `catalog_router_valid_fixture_passes`; `catalog_router_rejects_unsafe_raw_material`; source check: `rg -n 'KgCatalogRouterPreview::parse_json' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9569 | `no_change` | `crates/exo-economy/src/settlement.rs::AutomatedSettlementEvent` is constructed by `crates/exo-node/src/economy.rs` through `AutomatedSettlementEvent::from_inputs`; the node does not deserialize this event from a request, and the store reads only its own committed objects. | `crates/exo-economy/src/settlement.rs::tests::automated_settlement_succeeds_inside_preapproved_terms`; source check: `rg -n 'AutomatedSettlementEvent(::from_inputs)?' crates/exo-node/src/economy.rs crates/exo-economy/src/store.rs crates/exo-economy/src/settlement.rs` | — |
| design-9570 | `no_change` | `crates/exo-escalation/src/challenge.rs::ContestHold` is created through `admit_challenge(SignedChallengeAdmission)` and mutated through state-transition functions; `crates/exo-node/src/challenges.rs` does not deserialize a `ContestHold` from HTTP. | `crates/exo-escalation/src/challenge.rs::tests::audit_log_grows_with_transitions`; source check: `rg -n -e 'ContestHold' -e 'admit_challenge' crates/exo-node/src/challenges.rs crates/exo-escalation/src/challenge.rs` | — |
| design-9571 | `no_change` | `crates/exo-gatekeeper/src/error.rs::GatekeeperError::KernelIntegrityFailure` has no production constructor. If received by DAG DB mapping, `crates/exo-gateway/src/dagdb.rs::GatekeeperFailure::from_error` discards expected/actual values and returns fixed `database_unavailable` / `DAG DB database operation failed`. | `crates/exo-gateway/src/dagdb.rs::tests::gatekeeper_responses_use_static_sanitized_messages`; source check: `rg -n 'KernelIntegrityFailure' --glob '*.rs' --glob '!**/target/**'` | — |
| design-9577 | `no_change` | `crates/exo-gateway/src/bin/dagdb_writeback_sign.rs` is a standalone, explicit local-development/operator CLI. The fixture default is local-dev-only and compiled out of release behavior; no gateway router or deployment runtime calls the binary. | `dagdb_writeback_sign_parses_key_seed_env_source`; source check: `rg -n -e 'dagdb_writeback_sign' -e 'DEV_KEY_SEED_REL' -e 'LOCAL_DEV_GATEKEEPER_ENV' crates/exo-gateway/Cargo.toml crates/exo-gateway/src/bin/dagdb_writeback_sign.rs` | — |
| design-9578 | `no_change` | `crates/exo-gateway/src/bin/dagdb_writeback_sign.rs::run_writeback_sign` reports detailed failures only to the invoking local operator through `main`/stderr; it is not an HTTP response path or lower-privilege remote sink. | `dagdb_writeback_sign_runner_returns_real_environment_or_database_result`; source check: `rg -n -e 'run_writeback_sign' -e 'eprintln!' -e 'writeback_sign_connect_failed' crates/exo-gateway/src/bin/dagdb_writeback_sign.rs` | — |
| design-9596 | `no_change` | Detailed Shamir diagnostics remain typed library errors in `crates/exo-identity/src/error.rs`; the public WASM reconstruction boundary `crates/exochain-wasm/src/identity_bindings.rs::reconstruct_shamir_secret_json` maps every reconstruction error to static `SHAMIR_RECONSTRUCT_ERROR`. | `crates/exochain-wasm/src/identity_bindings.rs::tests::identity_shamir_reconstruct_error_does_not_echo_malformed_share_bytes` | — |
| design-9599 | `patch` | `crates/exo-identity/src/shamir.rs::Share::data` is `Zeroizing<Vec<u8>>`; custom `deserialize_share_data` accumulates into zeroizing storage and wipes replaced capacity, and coefficient/reconstructed-secret carriers are also zeroizing. | `shamir_share_data_uses_a_zeroizing_carrier`; `shamir_share_deserializer_accumulates_inside_zeroizing_storage`; `shamir_split_reconstruct_control_recovers_exact_secret` | `7ff7bfbc7cc7a9ea6773b1ec06b3ca2adc0934de`; `b497ac3e4759f412e4529434a944321a68e5d8c6` |
| design-9601 | `no_change` | `crates/exo-identity/src/shamir.rs::{Share, impl Debug for Share}` redacts secret share data. The exposed commitment is an intentionally serialized public integrity value needed to validate shares, so Debug creates no additional secret-bearing sink. | `share_debug_redacts_secret_share_data`; `shamir_share_json_wire_format_remains_byte_compatible` | — |
| design-9602 | `patch` | `crates/exo-identity/src/vault.rs::VaultEncryptor` keeps raw key storage private and no longer exposes `key_bytes`; the compile-fail doctest prevents callers from regaining the removed accessor. | `cargo test --doc -p exochain-identity`; source check: `! rg -n 'pub fn key_bytes' crates/exo-identity/src/vault.rs` | `7ff7bfbc7cc7a9ea6773b1ec06b3ca2adc0934de` |
| design-9608 | `patch` | `crates/exo-legal/src/dgcl144.rs::InterestedTransaction` fields are private; custom validated `Deserialize` uses `InterestedTransactionWire`, while all state changes flow through checked transition functions. | `safe_harbor_snapshot_rejects_inconsistent_state`; `failed_transaction_cannot_transition_to_verified`; `verified_transaction_cannot_reopen_voting` | `4639a7b86db4068537ca8a58c393018d1fe83246`; `58f4b4f46a504efdaf72d5dc2c01471f27be4d21` |
| design-9609 | `no_change` | `crates/exo-legal/src/error.rs::LegalError` is a typed library diagnostic. No node/gateway HTTP mapper consumes it; the WASM legal adapter operates on caller-owned inputs, so no internal file/SQL/secret source-to-remote-sink path was established. | `crates/exo-legal/src/error.rs::tests::error_display_all_variants`; source check: `rg -n 'LegalError' crates/exo-node crates/exo-gateway crates/exochain-wasm crates/exochain-sdk --glob '*.rs'` | — |
| design-9613 | `no_change` | `crates/exo-messaging/src/kex.rs::X25519SecretKey` has private `[u8; 32]` storage, `Zeroize` plus `#[zeroize(drop)]`, and manually redacted `Debug`; owned exchange paths borrow it and no owned clone sink was found. | `x25519_secret_key_source_does_not_expose_inner_bytes_or_plain_hex`; `x25519_secret_key_decoding_zeroizes_rust_owned_buffers` | — |
| design-9617 | `no_change` | Async AVC handlers access `crates/exo-node/src/avc.rs::AvcApiState::registry` through `with_registry_blocking`, which moves the entire lock/use operation into `tokio::task::spawn_blocking`; direct locks are synchronous startup/operator helpers. | `crates/exo-node/src/avc.rs::tests::router_uses_blocking_store_access` | — |
| design-9619 | `no_change` | `crates/exo-node/src/challenges.rs::{ChallengeTransitionAuthorization, verify_transition_authorization}` contains only public DID/key/signature material and binds the signature to hold state, transition, actor, time, detail, and authority-chain hash. No private-key or authorization formatting/log sink exists. | `unsigned_transition_request_is_rejected_without_mutating_hold`; source check: `rg -n -e 'SecretKey' -e 'authorization' crates/exo-node/src/challenges.rs` | — |
| design-9621 | `no_change` | `crates/exo-node/src/crosschecked_anchor_store.rs::{AnchorNodeIdentity, AnchorStoreConfig, AuthorityGovernanceAuthorizationV1, CrossCheckedScopeBindingV1, AuthorityRetirementV1}` contain public/verifying keys, hashes, and signatures, not signing secrets. | Source check: `rg -n -e 'SecretKey' -e 'private_key' -e 'signing_secret' -e 'secret_key' crates/exo-node/src/crosschecked_anchor_store.rs` | — |
| design-9622 | `no_change` | Detailed `crates/exo-node/src/crosschecked_anchor_store.rs::AnchorStoreError` remains internal. `crates/exo-node/src/crosschecked_anchor_http.rs::store_error_response` maps codec, authority, and internal signer/storage/governance/readback groups to fixed `invalid_request`, `authority_rejected`, or `recording_unavailable` responses. | Source check: `rg -n -e 'fn store_error_response' -e 'recording_unavailable' -e 'authority_rejected' -e 'invalid_request' crates/exo-node/src/crosschecked_anchor_http.rs` | — |
| design-9623 | `no_change` | Async handlers access `crates/exo-node/src/exoforge.rs::SharedForgeState` only through `read_forge_state` and `mutate_forge_state`; both move lock-held synchronous work into `spawn_blocking`. | `crates/exo-node/src/exoforge.rs::tests::async_handlers_do_not_lock_forge_state_directly` | — |
| design-9625 | `patch` | `crates/exo-node/src/identity.rs::load_or_create` performs one `read_private_file`; only typed `PrivateFileReadError::NotFound` selects creation. `crates/exo-node/src/private_file.rs::write_private_create_new` uses create-new/no-follow identity validation, and an `AlreadyExists` retry closes both exists/read and create/clobber races. | `identity.rs::tests::private_file_identity_rejects_permissive_and_symlink_keys_before_decode`; `private_file.rs::tests::private_file_read_returns_typed_not_found_and_uses_fixed_zeroizing_storage`; `private_file_create_new_is_owner_only_and_never_clobbers` | `bb3c9ff1409722849b20325dd56840fc7865b799` |
| design-9626 | `no_change` | `crates/exo-node/src/identity.rs::load_or_create` retains useful filesystem context for local startup/operator failure, but all callers are startup/CLI paths in `crates/exo-node/src/main.rs`; no HTTP response sink exists. | Source check: `rg -n 'identity::load_or_create' crates/exo-node/src --glob '!identity.rs'` | — |
| design-9636 | `no_change` | `crates/exo-node/src/passport.rs::{PASSPORT_CONCURRENCY_LIMIT, passport_router}` actively installs `ConcurrencyLimitLayer::new(PASSPORT_CONCURRENCY_LIMIT)`; state access is also isolated from async workers. | `crates/exo-node/src/passport.rs::tests::passport_async_handlers_use_blocking_state_access`; source check: `rg -n -e 'PASSPORT_CONCURRENCY_LIMIT' -e 'ConcurrencyLimitLayer' crates/exo-node/src/passport.rs` | — |
| design-9641 | `no_change` | `crates/exo-node/src/reactor.rs::validate_governance_proposal_payload` receives governance payloads only after `crates/exo-node/src/wire.rs::deserialize_governance_payload` enforces `MAX_WIRE_GOVERNANCE_PAYLOAD_BYTES = 64 KiB` before reactor CBOR decoding. | `crates/exo-node/src/wire.rs::tests::decode_rejects_governance_event_with_oversized_payload` | — |
| design-9643 | `patch` | `crates/exo-node/src/root_genesis.rs::{root_error_to_response, internal_portal_error}` preserve intended 4xx contracts, log internal `RootError` diagnostics server-side, and return fixed internal-error text for 5xx failures. | `root_error_mapper_redacts_internal_error_details`; `root_error_redaction_preserves_existing_client_error_contracts` | `f512f8f45f66e0733d764a3ceb17de4bebca4fe7` |
| design-9645 | `no_change` | The cited root CLI inputs are private local ceremony DTOs rather than a remote sink. Current overlapping hardening in `crates/exo-node/src/root_genesis_cli.rs` makes `PrivateCertifierMaterial` and private command carriers zeroizing and redacted/no-`Debug`. | `private_file_root_cli_secret_material_is_redacted_zeroizing_and_json_compatible`; `private_file_root_cli_secret_dtos_cannot_regain_debug_or_unchecked_parsing`; `private_file_root_cli_decodes_private_secrets_only_into_zeroizing_storage` | — |
| design-9647 | `no_change` | `crates/exo-node/src/sentinels.rs::{SharedSentinelState, collect_sentinel_statuses_blocking}` moves status collection and all lock-held synchronous work away from async executor threads; replacement/read helpers follow the same rule. | `crates/exo-node/src/sentinels.rs::tests::sentinel_async_paths_do_not_lock_std_mutexes_directly` | — |
| design-9651 | `no_change` | `crates/exo-node/src/zerodentity/api.rs::{ApiState, with_store_blocking}` isolates every store operation in `spawn_blocking`; signed-write and owner-session verification use the same helper and async handlers do not lock the standard mutex directly. | `crates/exo-node/src/zerodentity/api.rs::tests::api_async_handlers_use_blocking_store_access` | — |
| design-9668 | `no_change` | `crates/exo-pdp/src/http.rs` calls `SharedPdp::lock` only in await-free synchronous sections after any middleware await; `crates/exo-pdp/src/service.rs::SharedPdp` contains no async function or await point. | Source checks: `rg -n -e 'async fn' -e '\.await' -e 'pdp\.lock\(' crates/exo-pdp/src/http.rs`; `rg -n -e '\basync\b' -e '\bawait\b' crates/exo-pdp/src/service.rs` | — |
| design-9670 | `no_change` | `crates/exo-pdp/src/http.rs::{MAX_PDP_BODY_BYTES, build_pdp_router, build_pdp_read_router, build_pdp_mutation_router}` installs a 1 MiB `DefaultBodyLimit` on every exported router before JSON extraction. | `crates/exo-pdp/src/http.rs::tests::exported_router_rejects_oversized_mutation_body_before_json_extraction` | — |
| design-9673 | `no_change` | The owned untrusted route to `crates/exo-pdp/src/mandate.rs::WireMandate` and nested caveat/rail vectors is behind the PDP router's 1 MiB pre-extraction `DefaultBodyLimit`; no unbounded sibling runtime parser was found. | `crates/exo-pdp/src/http.rs::tests::exported_router_rejects_oversized_mutation_body_before_json_extraction` | — |
| design-9676 | `no_change` | `crates/exo-pdp/src/service.rs::SharedPdp::lock` is a synchronous service boundary; the module has no async/await, and `crates/exo-pdp/src/http.rs` callers do not retain a guard across suspension. | Source checks: `rg -n -e '\basync\b' -e '\bawait\b' crates/exo-pdp/src/service.rs`; `rg -n -e 'async fn' -e '\.await' -e 'pdp\.lock\(' crates/exo-pdp/src/http.rs` | — |
| design-9678 | `no_change` | `crates/exo-pdp/src/service.rs::PdpSnapshot` fields are private and used only for export/import serialization; no owned format/log sink exists. `crates/exo-node/src/pdp_store.rs` reads owner-only state behind a 64 MiB pre-CBOR cap and logs only paths. | `crates/exo-node/src/pdp_store.rs::tests::pdp_snapshot_bounds_are_enforced_before_cbor_parse`; source check: `rg -n -e 'PdpSnapshot' -e 'format!' -e 'tracing::' crates/exo-pdp/src/service.rs crates/exo-node/src/pdp_store.rs` | — |
| design-9681 | `no_change` | `crates/exo-proofs/src/snark.rs::ProvingKey` contains public circuit structure/fingerprint, not witness material. The feature-gated pedagogical legacy verifier now fails closed with `UnauditedImplementation`, so the reported Debug concern has no accepting production verifier behind it. | `crates/exo-proofs/src/snark.rs::tests::legacy_snark_verify_refuses_forged_public_hash_chain` under `unaudited-pedagogical-proofs` | — |
| design-9686 | `no_change` | The report-cited `crates/exo-proofs/src/zkml.rs::DaubertChecklist` has a variable-length `known_error_rate`, but its owned CBOR decoding goes through `crates/exo-proofs/src/verifier.rs::{decode_cbor, MAX_VERIFIER_CBOR_BYTES}`, which rejects oversized input before deserialization; no HTTP or CLI deserialization entrypoint for this type was found. | `crates/exo-proofs/src/verifier.rs::canonical_encoding_contract_tests::decode_cbor_rejects_oversized_inputs_before_deserialization`; caller/source check: `rg -n 'DaubertChecklist' crates -g '*.rs'` | — |
| design-9692 | `patch` | `crates/exo-root/src/seal.rs::SealedShare` deliberately exposes only public transport artifacts (salt, nonce, ciphertext, tag). The patch-compatible public DKG plaintext carriers preserve their legacy raw fields, `Clone`, wire shape, and caller-owned moves; they redact `Debug` and support explicit zeroization, but do not claim automatic wiping after callers move or clone the bytes. `signing.rs::RootSigningNonces` and private root CLI passphrase/share DTOs remain zeroizing-on-drop and redacted/no-`Debug`. | `crates/exo-root/tests/dkg_patch_compat.rs::{legacy_public_fields_remain_directly_movable_and_destructurable,legacy_wire_shape_is_unchanged_while_debug_redacts_nested_secrets}`; `dkg.rs::tests::{legacy_secret_dkg_byte_carriers_support_explicit_zeroize,secret_dkg_deserializers_round_trip_all_secret_carriers}`; `secret_dkg_debug_redacts_every_private_package`; `secret_round_two_recipient_packages_are_fully_redacted`; `signing.rs::tests::secret_signing_nonce_bytes_zeroize_on_drop`; `secret_signing_nonce_debug_is_redacted_and_wire_compatible` | `17886a35bef479465da68c7099087996eeb9f606`; `df01c9fb4a69e8d31137f2b59afeca497c4a66da`; `c1946ca9a1d16a078c812bdc4f57859e1af50730`; `bb3c9ff1409722849b20325dd56840fc7865b799`; `e8d04a94e2762e67e49481e20eae89dcd9a8729d`; `65527ba710f722264447e0a63c0d62a3f1a33b61`; test evidence `760613e6d24cef59a3167dbfaec6a0e0dae21aca`; `3b98fd11a14bfa048416a6d2b89d26078eba0e94` |
| design-9701 | `no_change` | `crates/exochain-sdk/src/consent.rs::{BailmentProposal, validate_bailment_proposal}` performs custom deserialization validation, but repository-wide use is confined to the SDK module, documentation, and tests; there is no owned attacker-controlled runtime deserializer. | Source check: `rg -n '\bBailmentProposal\b' --glob '*.rs' --glob '!target/**' .` | — |
| design-9705 | `no_change` | `crates/exochain-sdk/src/governance.rs::Decision` is constructed/serialized inside the SDK module and re-exported; no owned network/file deserializer caller for this SDK type exists. | Source check: `rg -n -e 'exochain_sdk::governance::Decision' -e 'governance::Decision' -e '\bDecision\b' --glob '*.rs' --glob '!target/**' crates/exochain-sdk` | — |
| design-9707 | `no_change` | `crates/exochain-sdk/src/identity.rs::Identity` does not implement `Clone`, its secret field is private, and it exposes no secret accessor; underlying `crates/exo-core/src/types.rs::SecretKey` has `#[zeroize(drop)]`. | `crates/exochain-sdk/src/identity.rs::tests::debug_redacts_secret`; source check: `sed -n '83,340p' crates/exochain-sdk/src/identity.rs` | — |
| design-9708 | `no_change` | `crates/exochain-sdk/src/kernel.rs::with_authority_identity` moves `Identity` into an `AuthoritySigner` `Arc` closure. Dropping the last closure reference drops the captured identity, reaching the underlying `SecretKey` and its `#[zeroize(drop)]` guarantee. | `crates/exo-core/src/types.rs::tests::secret_key_zeroize_on_drop`; source check: `sed -n '183,320p' crates/exochain-sdk/src/kernel.rs` | — |

## Late implementation-series overlap revalidation

Commit `f3845873` modifies `crates/exo-node/src/avc.rs`, which also owns
design-9540 and design-9617. It does not modify `read_timestamp_response`, its
byte ceiling, or `with_registry_blocking`. Both timestamp reader limit tests
passed (2 tests), and the exact blocking-store-access guard passed (1 test) at
checkpoint `e73dcf53`. FORMAL-9616's root-trust selectors in the same file were
also rechecked. These focused checks do not replace the complete final gate
corpus.

Test-only commits `760613e6` and `3b98fd11` subsequently expanded the
design-9692 regression across every patch-compatible DKG secret carrier,
explicitly verified zeroization after JSON/CBOR decoding, and retained
serialized fixtures in zeroizing buffers. At `3b98fd11`, DKG source coverage
was 325/325 lines and complete `exo-root` coverage was 1,146/1,146 lines. The
source-checkpoint feature matrix later passed at `368721a1` for all six node
variants, gateway GraphQL, pedagogical proofs, and `conformance-test-root`.
`EXO_TS_ROOT` was unset, so the TypeScript conformance-root path remains an
explicit evidence gap.

## Mechanical reconciliation

The ordered report anchors were parsed from every `body-design-*` element in the Design Observations section. The table rows above were then extracted with `^\| (design-[0-9]+) \|`. The verifier asserts:

- report count = 52;
- report unique count = 52;
- ledger row count = 52;
- ledger unique count = 52;
- classification count = 52 with no duplicates;
- exact report/ledger set equality;
- exact report/ledger order equality; and
- sorted numeric ID-set SHA-256 (with the `design-` prefix removed) = `4735fd41ff8e84f85a5502a83635f0b00673a9f754ea3098039199e41b3637f6`.

Re-run from the repository root:

```bash
python3 - <<'PY'
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
import re

class IdParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, tag, attrs):
        element_id = dict(attrs).get('id', '')
        if element_id.startswith('body-design-'):
            self.ids.append(element_id.removeprefix('body-'))

report = Path('/Users/bobstewart/Downloads/Exochain-code-review-report-run4.html')
ledger = Path('docs/audit/exochain-code-review-report-run4-design-evidence-2026-09-04.md')
parser = IdParser()
parser.feed(report.read_text())
report_ids = parser.ids
ledger_text = ledger.read_text()
ledger_ids = re.findall(r'^\| (design-[0-9]+) \|', ledger_text, re.MULTILINE)
classification_groups = re.findall(
    r'^\| (EXOCHAIN core|Core runtime adapter) \((\d+)\) \| `([^`]+)` \|$',
    ledger_text,
    re.MULTILINE,
)
expected_class_counts = {'EXOCHAIN core': 22, 'Core runtime adapter': 30}
assert {name: int(declared) for name, declared, _ in classification_groups} == expected_class_counts
assert all(int(declared) == len(group.split(',')) for _, declared, group in classification_groups)
classification_ids = [
    item.strip()
    for _, _, group in classification_groups
    for item in group.split(',')
]
assert len(report_ids) == len(set(report_ids)) == 52
assert len(ledger_ids) == len(set(ledger_ids)) == 52
assert len(classification_ids) == len(set(classification_ids)) == 52
assert ledger_ids == report_ids
assert set(classification_ids) == set(ledger_ids)
numeric_ids = [item.removeprefix('design-') for item in ledger_ids]
digest = sha256(('\n'.join(sorted(numeric_ids)) + '\n').encode()).hexdigest()
assert digest == '4735fd41ff8e84f85a5502a83635f0b00673a9f754ea3098039199e41b3637f6'
print(f'design_evidence_set=PASS count={len(ledger_ids)} sha256={digest}')
print(f'design_classification_set=PASS count={len(classification_ids)}')
PY
```

Expected and re-observed result for this exact-set check:

```text
design_evidence_set=PASS count=52 sha256=4735fd41ff8e84f85a5502a83635f0b00673a9f754ea3098039199e41b3637f6
design_classification_set=PASS count=52
```

## Explicit ambiguities and residual design cautions

- The local DAG DB writeback signer intentionally retains a relative fixture path for explicitly selected development mode. No production router/deployment caller exists, but an operator who invokes that development binary from an attacker-controlled working directory would still be outside the reviewed trust assumptions.
- Several exported library types remain theoretically deserializable or cloneable. Their `no_change` disposition is based on the absence of an owned attacker-controlled caller or sensitive sink at this audited snapshot, not a claim that future callers need no ingress cap or zeroization review.
- Detailed typed library errors remain in some core modules for internal diagnosis. The disposition depends on verified fixed external adapters; any new adapter must preserve those mappings.
- Public keys, signatures, commitments, salts, nonces, ciphertext, hashes, and circuit fingerprints were treated as public protocol/integrity artifacts. Private signing keys, raw symmetric keys, Shamir share bytes, DKG secret packages, signing nonces, plaintext shares, and passphrases were treated as secrets.
- This matrix records source/caller/test disposition at the committed source
  checkpoint. Complete scan `429b3137-c1ad-49c9-8fd8-ea7baf030d69` found a
  separate High release-credential boundary outside these 52 IDs. The workflow
  binding was corrected at `111f7955`, and parser-differential guard hardening
  followed at `b5dcb89b`, but exclusive protected-environment custody remains
  unproven. Organization inheritance was unresolved at that historical checkpoint;
  the current applicability section above supersedes that uncertainty. This
  matrix does not by itself prove the final release gate is green or that
  release `0.2.6` has been tagged, published, deployed, or runtime-verified.
