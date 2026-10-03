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

# DF-PROTOCOL-001 Slice 3 Council, AI-IRB, and Stop Authority Implementation Plan

## Authoring objective and authority boundary

Author the complete implementation plan for section 15 item 3 of the canonical
`DF-PROTOCOL-001` design. Save it as
`docs/superpowers/plans/2026-07-16-df-protocol-001-03-council-ai-irb-stop-authority.md`.
The plan must use the `superpowers:writing-plans` header, checkbox steps, exact
interfaces, complete RED tests, exact commands and expected failures, complete
minimum GREEN listings, affected suites, staged paths, and one independently
reviewable commit per gate.

This file is the executable Slice 3 implementation plan promoted from the
Wave 4 author brief and reconciled to Wave 20-approved Slice 1/2 plans. It is
not compiled code, a credential, an operator bootstrap capability, a signature,
constitutional ratification, binding authority, a deployment, a runtime
observation, a release, or a publication. It supersedes Wave 3 briefs in full;
an implementer must not combine a Wave 3 signature or target with a Wave 4/this
plan proof. Implementation begins only from a clean reviewed design-branch head
(current: `72ac3ec9…` on `bob-stewart/decision-forum-peer-reviewed-protocol-design`,
or a successor Slice 3 implementation branch cut from that head). Record the
base commit, tree, Slice 2 plan hash, and same-head Slice 1/2 approvals before
the first RED.

## Frozen evidence basis

| Evidence | Exact value |
|---|---|
| Repository | `/Users/bobstewart/.codex/worktrees/b080/exochain` |
| Design branch HEAD (Slice 3 plan base) | `72ac3ec99db40c18b3e3b71483192f6a49ec4c5d` |
| Canonical design | `docs/superpowers/specs/2026-07-16-decision-forum-peer-reviewed-protocol-governance-design.md`; SHA-256 `02d8b3feb5f3a9cb6b00fd52c45ccb70045336e77a9f81ffe39cdcc3a97e69bc` |
| Delivery map | `docs/superpowers/plans/2026-07-16-df-protocol-001-delivery-map.md`; SHA-256 `4d4f3e10f713d3eec2409c71680c0f1c2ced35379b869d0602a31089650b4c8e` |
| Slice 1 plan (Wave 20 post-repair) | SHA-256 `4e3a97540dae01dbe0b9ae9b162fc225a67e5f51d2072762f19d901c123ea081` |
| Slice 2 plan (Wave 20 post-repair, dual-approved) | `docs/superpowers/plans/2026-07-16-df-protocol-001-02-core-protocol-receipt-model.md`; SHA-256 `fa804fefdb56d9595afc6517923bb2316b6b3917ddae3a6110cf41f03036fb22` |
| Wave 20 fix-spec | SHA-256 `c4a26a375d7beb26f3b672675ca9ed2154254fd214e9bab7293b17afa7a4635b` |
| Slice 3 Wave 4 author brief (this plan's engineering source) | `/Users/bobstewart/.codex/backups/exochain/df-protocol-001/slice-3-author-brief-wave-4.md` |
| Slice 3 read-only inventory | `/Users/bobstewart/.codex/backups/exochain/df-protocol-001/slice-3-readonly-inventory.md` |
| Frozen D9 predecessor BLAKE3 | `c1e89db47a30849d41e6db9c4c23d52d9dfbf3a820f2695dcdbcade6d42bd6af` |
| Planned D9 Amendment 1 BLAKE3 | `38330feabc0d18c5d00eb7268631c6d92dc608118f465fc84e07871bd7217c81` |
| PR | https://github.com/exochain/exochain/pull/809 (documentation boundary; no merge/deploy/ratify/release) |

### Wave 20 / Slice 2 reconciliation (mandatory pre-RED)

Slice 2 is **plan-approved** at the hash above (Wave 20 findings 1–5 dual-approved;
semantic guard GREEN; plan-only `cargo test --no-run` green without diagnostic
shim). Implementation of production crates is still future work. Before Gate 00
RED, recompute the Slice 2 plan SHA-256 at the implementation base and stop if
it differs from `fa804fef…`.

**Domain inventory delta:** Wave 4 assumed Slice 2 `ProtocolHashDomain::ALL`
length **26** and prescribed extension to **68** (+42 Slice 3 domains). The
approved Wave 20 Slice 2 plan carries **47** domain variants
(`pub const ALL: [Self; 47]`). Slice 3 therefore:

1. Appends the **exact 42** domain rows listed below **after** the frozen Slice 2
   47-variant inventory (no renumbering of Slice 2 rows).
2. Sets `ProtocolHashDomain::ALL` to **`[Self; 89]`** (47 + 42), not 68.
3. Extends every `as_str` / cross-impl known-answer table to the full 89-set.
4. Treats Wave 4 gate assertions that hard-code `assert_eq!(…ALL.len(), 89)` as
   **`89`**.

**Structural contracts already present in approved Slice 2 (do not re-break):**

- E-STOP structural validation already uses nonempty provider-only active set,
  subset approvals, checked `ceil(2*n/3)`, and recomputed result (Wave 20
  `E_STOP_DENOMINATOR` / `verify_estop_against_authenticated_roster`).
- Valid reject/missing votes remain structurally valid and recompute
  `NotUnanimous` (Wave 20 `DISSENT_NON_REGRESSION`).
- Pre-reveal `ReviewAssignment` exposes no `seat_id` /
  `seat_attestation_hash` / `provider` / `controller` (Wave 20
  `BLIND_CUSTODY`).
- Genesis uses `VerifiedHistoricalReviewRevealV1`; blind reveal keeps
  `VerifiedReviewRevealV1`.
- `CommitmentScheme` closed set is **35** fields in both Slice 1 and Slice 2.
- Purpose-specific governed signatures cross-bind opaque
  `VerifiedPurposeAuthorityFactsV1` (Wave 20 `GOVERNED_SIGNATURE_AUTHORITY`).

Slice 3 **owns** converting authenticated structural packages into opaque
authority proofs (ratification + qualification + unanimity + stop/reset/
promotion). It does **not** reintroduce all-approve-only package integrity or
exactly-three E-STOP validation.

**Inventory C-01 / C-02 disposition:** The July-22 inventory critical findings
targeted pre-Wave-20 Slice 2 text. Re-verify at RED time against the approved
`fa804fef…` plan; only residual gaps (missing production trust constructor,
typed human AAR/RCA/RESET signing payloads still incomplete as authority
proofs, human-only kernel quorum separation) are in-scope for Slice 3 Gates
00–11. Do not silently reopen Wave 20 closed predicates.

**Implementation base rule:** Start from reviewed design-branch head
`72ac3ec9…` (or its successor merge). Record base SHA, tree, Slice 2 plan
hash, and both same-head Slice 1/2 approvals before the first RED. This plan
is engineering only — not ratification, credentials, deployment, or
publication.

## Scope, classification, licensing, and immutable constraints

Every listed Rust, test, vector, governance, and implementation-evidence path is
EXOCHAIN core. New Rust and Markdown files carry the Apache-2.0 header and SPDX
identifier. No commercial right follows from a core license. Slice 3 changes no
gateway, migration, SQL, DAG DB runtime, REST, GraphQL, SDK, MCP, WASM, node,
deployment, `web/`, CrossChecked, CyberMedica, LiveSafe, LegalDyne, or other
proprietary path. Migrations are `None`.

Slice 3 owns pure qualification, canonical verification, decision derivation,
and pending notification requirements. Slice 4 owns authenticated ingress,
operator configuration loading, persistence, projection-plus-receipt atomicity,
delivery attempts, materialized current state, and transport bypass closure.
Slice 3 never fabricates a receipt or claims REST/GraphQL/SDK/MCP/runtime closure.

Add no Rust or npm dependency. `Cargo.lock` and every npm lockfile remain
byte-identical. Production logic uses integer or fixed-point arithmetic,
`BTreeMap`/`BTreeSet`, caller-supplied UUID/HLC, checked arithmetic, canonical
CBOR, and domain-separated BLAKE3. It uses no floating point, unordered map/set,
system time, random ID, direct JSON hash, unsafe code, unchecked authority
constructor, or `unwrap`/`expect` outside tests.

The following remain exact:

1. Council and AI-IRB each have exactly five eligible seats and required count
   five. Missing, recused, conflicted, expired, absent, abstaining, or rejecting
   seats never reduce either denominator.
2. Binding requires all four provider classes and at least two independent
   evidence classes including `IndependentNonProviderEvidence`.
3. E-STOP provider approval is separate from eligible unanimity and uses checked
   `ceil(2*n/3) = (2*n + 2)/3`: `1->1`, `2->2`, `3->2`, `4->3`; zero and
   overflow error. DF-PROTOCOL-001 retains four provider classes even when a seat
   is unavailable; replacement requires ratification.
4. `EstopAuthorization` has exactly nine fields. The pending stop has no receipt
   root. Slice 4 alone creates the materialized ninth field.
5. Missing exact D9 ratification produces `Advisory`, never `Binding`.
6. Chair approval never cures dissent or a missing vote. Chair rejection creates
   only a signed scoped HumanOverride hold.
7. Systemic learning is context only and cannot enact code, policy, authority,
   envelope, phase, or constitutional change.

## Wave 3 audit closure matrix

| Finding | Wave 4 binding correction |
|---|---|
| W3-01 | `VerifiedPackageBoundaryV1`, `VerifiedSuccessorPackageBoundaryV1`, ordered verified receipt facts, and the exact stop receipt are the only operands of `verify_stop_continuation`; prior version, prior chain, constitution, package roots, terminal facts, and stop membership are derivable. |
| W3-02 | One `ResetAuthorizationTargetV1` commits the complete stop/successor/continuation/AAR-RCA/CAPA/recurrence/body-roster/Chair conjunction. Council, AI-IRB, and Chair all sign the same target hash. Three exact human-proof producers are frozen below. |
| W3-03 | Progressive body targets commit exact event, monitoring, threshold, observation, and threshold-result hashes. Promotion body targets commit the exact verified progressive-decision hash in addition to event, phases, envelope, and scope. |
| W3-04 | `protocol/domains.rs` gains the complete 42-domain Slice 3 inventory, extends `ProtocolHashDomain::ALL` from 47 to 89, and drives independent Rust/TypeScript canonical-CBOR known-answer vectors. |
| W3-05 | The file map includes `authority/mod.rs`, `receipt/segment.rs`, `types/mod.rs`, `cross_impl_tests.rs`, and `df_protocol_001_dissent_chair.rs`. Gate 00 assigns every interface to an exact function-pointer type and compile-fail doctests prove private fields, package-private methods, and required registry references. Gates 09 and 10 have complete RED code and commands. |
| W3-06 | The D9 RED uses two frozen mutation tables. Public changed bytes expect `exact_markdown_blake3`; internal exact-Article mapping mutations expect `article_mapping`; every other input has its own exact field. |
| W3-07 | The package boundary retains `protocol_identity.chair_did`; `VerifiedPackageChairAuthorityV1` binds it to immutable operator-rooted authority; monitoring requires `escalation_destination == chair_did`; typed `Chair` destinations are constructed only from that opaque proof. |
| W3-08 | Missing E-STOP trust registry is a compile-fail/API property. Runtime tests cover only supplied opaque registries that are wrong by tenant, package, root, roster, context, or seat. The production reference remains non-optional. |

## Canonical hashing and signing contract

`domain_hash` remains the single Slice 2 implementation: canonical CBOR of
`(domain.as_str(), value)` followed by BLAKE3. Every signature envelope stores
the exact expected domain hash in `signed_payload_hash`, sets the exact
`SignedPayloadTarget`, and signs those 32 hash bytes with Ed25519. Raw JSON,
display strings, generic labels, and caller-supplied digest aliases never become
canonical inputs.

### Complete Slice 3 domain registry

Add these variants and exact strings to
`crates/decision-forum/src/protocol/domains.rs`. Append them in this exact order
after the frozen 47 Slice 2 variants, extend `ProtocolHashDomain::ALL` to
`[Self; 89]`, and add one exhaustive `as_str` arm per row. The first two rows
mirror the identical public constants owned upstream by
`exo-gatekeeper::decision_forum_trust`; Gatekeeper does not import Decision
Forum.

| # | `ProtocolHashDomain` variant | Exact domain string | Exact canonical value |
|---:|---|---|---|
| 1 | `DecisionForumTrustRootManifestV1` | `exo.gatekeeper.decision_forum.trust_root_manifest.v1` | `DecisionForumTrustRootManifestV1` |
| 2 | `DecisionForumOperatorBootstrapPolicyV1` | `exo.gatekeeper.decision_forum.operator_bootstrap_policy.v1` | immutable bootstrap policy fields |
| 3 | `D9Amendment1ReceiptSigningPayloadV1` | `exo.decision_forum.d9_amendment_1.receipt_signing_payload.v1` | `D9Amendment1ReceiptSigningPayloadV1` |
| 4 | `PackageAuthorityBoundaryV1` | `exo.decision_forum.package_authority_boundary.v1` | `PackageAuthorityBoundaryHashInputV1` |
| 5 | `PackageChairAuthorityV1` | `exo.decision_forum.package_chair_authority.v1` | `PackageChairAuthorityHashInputV1` |
| 6 | `ClaimThresholdDefinitionV1` | `exo.decision_forum.claim_threshold_definition.v1` | `ClaimThresholdDefinitionV1` |
| 7 | `MonitoringPlanAuthorityV1` | `exo.decision_forum.monitoring_plan_authority.v1` | `MonitoringPlanAuthorityHashInputV1` |
| 8 | `ActionBindingV1` | `exo.decision_forum.action_binding.v1` | `ActionBindingV1` |
| 9 | `ProtocolActionDispositionSigningPayloadV1` | `exo.decision_forum.protocol_action_disposition_signing_payload.v1` | `ProtocolActionDispositionSigningPayloadV1` |
| 10 | `EligibleUnanimityDecisionV1` | `exo.decision_forum.eligible_unanimity_decision.v1` | `EligibleUnanimityDecisionHashInputV1` |
| 11 | `DissentDecisionV1` | `exo.decision_forum.dissent_decision.v1` | `DissentDecisionHashInputV1` |
| 12 | `PendingNotificationRequirementV1` | `exo.decision_forum.pending_notification_requirement.v1` | `NotificationRequirementHashInputV1` |
| 13 | `ProgressiveThresholdResultV1` | `exo.decision_forum.progressive_threshold_result.v1` | `ProgressiveThresholdResultV1` |
| 14 | `ProgressiveEventAuthorizationTargetV1` | `exo.decision_forum.progressive_event_authorization_target.v1` | `ProgressiveEventAuthorizationTargetV1` |
| 15 | `ProgressiveEventDecisionV1` | `exo.decision_forum.progressive_event_decision.v1` | `ProgressiveEventDecisionHashInputV1` |
| 16 | `AdverseEventDecisionV1` | `exo.decision_forum.adverse_event_decision.v1` | `AdverseEventDecisionHashInputV1` |
| 17 | `PhasePromotionAuthorizationTargetV1` | `exo.decision_forum.phase_promotion_authorization_target.v1` | `PhasePromotionAuthorizationTargetV1` |
| 18 | `PhasePromotionDecisionV1` | `exo.decision_forum.phase_promotion_decision.v1` | `PhasePromotionDecisionHashInputV1` |
| 19 | `ActiveRosterSnapshotV1` | `exo.decision_forum.active_roster_snapshot.v1` | `ActiveRosterSnapshotHashInputV1` |
| 20 | `EvidenceFloorV1` | `exo.decision_forum.evidence_floor.v1` | `EvidenceFloorHashInputV1` |
| 21 | `EstopActionDispositionSetV1` | `exo.decision_forum.estop_action_disposition_set.v1` | `EstopActionDispositionSetHashInputV1` |
| 22 | `EstopProviderApprovalSetV1` | `exo.decision_forum.estop_provider_approval_set.v1` | `EstopProviderApprovalSetHashInputV1` |
| 23 | `PendingEstopDecisionV1` | `exo.decision_forum.pending_estop_decision.v1` | `PendingEstopDecisionHashInputV1` |
| 24 | `EstopReferenceV1` | `exo.decision_forum.estop_reference.v1` | `EstopReferenceHashInputV1` |
| 25 | `CapaOwnerActionSigningPayloadV1` | `exo.decision_forum.capa_owner_action_signing_payload.v1` | `CapaOwnerActionSigningPayloadV1` |
| 26 | `CapaOpenDecisionV1` | `exo.decision_forum.capa_open_decision.v1` | `CapaOpenDecisionHashInputV1` |
| 27 | `CapaCompletionV1` | `exo.decision_forum.capa_completion.v1` | `CapaCompletionHashInputV1` |
| 28 | `RecurrenceResultSigningPayloadV1` | `exo.decision_forum.recurrence_result_signing_payload.v1` | `RecurrenceResultSigningPayloadV1` |
| 29 | `RecurrenceResultV1` | `exo.decision_forum.recurrence_result.v1` | `RecurrenceResultHashInputV1` |
| 30 | `SystemicLearningDecisionV1` | `exo.decision_forum.systemic_learning_decision.v1` | `SystemicLearningDecisionHashInputV1` |
| 31 | `EventCloseAuthorizationTargetV1` | `exo.decision_forum.event_close_authorization_target.v1` | `EventCloseAuthorizationTargetV1` |
| 32 | `EventCloseDecisionV1` | `exo.decision_forum.event_close_decision.v1` | `EventCloseDecisionHashInputV1` |
| 33 | `HumanClassificationSigningPayloadV1` | `exo.decision_forum.human_classification_signing_payload.v1` | `HumanClassificationSigningPayloadV1` |
| 34 | `HumanClassificationStatementV1` | `exo.decision_forum.human_classification_statement.v1` | complete signed `HumanClassificationStatementV1` |
| 35 | `ChairInvestigatorDesignationSigningPayloadV1` | `exo.decision_forum.chair_investigator_designation_signing_payload.v1` | `ChairInvestigatorDesignationSigningPayloadV1` |
| 36 | `HumanInvestigatorDesignationV1` | `exo.decision_forum.human_investigator_designation.v1` | complete signed `HumanInvestigatorDesignationV1` |
| 37 | `HumanAarRcaSigningPayloadV1` | `exo.decision_forum.human_aar_rca_signing_payload.v1` | `HumanAarRcaSigningPayloadV1` |
| 38 | `HumanAarRcaV1` | `exo.decision_forum.human_aar_rca.v1` | `HumanAarRcaHashInputV1` |
| 39 | `ChairResetAuthorizationSigningPayloadV1` | `exo.decision_forum.chair_reset_authorization_signing_payload.v1` | `ChairResetAuthorizationSigningPayloadV1` |
| 40 | `ResetAuthorizationTargetV1` | `exo.decision_forum.reset_authorization_target.v1` | `ResetAuthorizationTargetV1` |
| 41 | `StopContinuationV1` | `exo.decision_forum.stop_continuation.v1` | `StopContinuationHashInputV1` |
| 42 | `ResetDecisionV1` | `exo.decision_forum.reset_decision.v1` | `ResetDecisionHashInputV1` |

No Slice 3 hash may use a string outside this registry except the existing
`decision.forum.constitution_amendment_signature.v1` message returned by
`amendment_signature_message`. The D9 receipt uses row 3, replacing Wave 3's
less precise receipt label.

Every `*HashInputV1` in the table is a private `Serialize` struct with the exact
ordered fields below. It is not an alias for a caller digest. A result's own hash
field and signatures are excluded; all other authoritative fields are included.

| Hash input | Exact ordered fields |
|---|---|
| `PackageAuthorityBoundaryHashInputV1` | `tenant_id`, `protocol_id`, `protocol_version_hash`, `final_package_root`, `prior_version_hash`, `constitution_hash`, complete `prior_execution`, `chair_did` |
| `PackageChairAuthorityHashInputV1` | `tenant_id`, `protocol_id`, `protocol_version_hash`, `final_package_root`, `chair_did`, `chair_signing_key_id`, `chair_authority_chain_hash`, `package_boundary_hash`, `root_manifest_hash` |
| `MonitoringPlanAuthorityHashInputV1` | `tenant_id`, `protocol_id`, `protocol_version_hash`, `final_package_root`, `package_boundary_hash`, sorted `thresholds_by_claim`, `chair_did`, `chair_authority_hash`, sorted `reporting_destinations`, sorted `event_payload_type_domains`, `max_iterations`, `repeat_failure_limit` |
| `EligibleUnanimityDecisionHashInputV1` | row-8 `action_binding_hash`, `seat_kind`, sorted `eligible_seat_ids`, sorted `approve_seat_ids`, sorted `provider_classes`, sorted `evidence_classes`, `eligible_count`, `approve_count`, `required_count`, `result`, `computed_at` |
| `DissentDecisionHashInputV1` | `dissent_id`, `seat_id`, `context`, `effect`, row-8 `action_binding_hash`, `signed_disposition_hash`, `recorded_at` |
| `NotificationRequirementHashInputV1` | `tenant_id`, `protocol_id`, `protocol_version_hash`, `final_package_root`, complete `subject`, `scope_hash`, `cause`, `verified_chair_authority_hash`, sorted `required_destinations`, `required_at` |
| `ProgressiveEventDecisionHashInputV1` | `event_id`, `event_hash`, `scope_hash`, `final_package_root`, `monitoring_plan_hash`, `progressive_target_hash`, `threshold_definition_hash`, `observed_evidence_hash`, `threshold_result_hash`, `council_proof_hash`, `ai_irb_proof_hash` |
| `AdverseEventDecisionHashInputV1` | `event_id`, `event_hash`, `scope_hash`, `final_package_root`, `monitoring_plan_hash`, `containment_required`, `continuing_review_required`, `council_proof_hash`, `ai_irb_proof_hash` |
| `PhasePromotionDecisionHashInputV1` | `promotion_id`, `protocol_version_hash`, `final_package_root`, `scope_hash`, `from_phase`, `to_phase`, `envelope_hash`, `progressive_event_id`, `progressive_event_hash`, `progressive_decision_hash`, `promotion_target_hash`, `council_proof_hash`, `ai_irb_proof_hash`, `promoted_at` |
| `ActiveRosterSnapshotHashInputV1` | `protocol_version_hash`, `final_package_root`, `trust_registry_binding_hash`, sorted `active_provider_classes`, sorted `active_ai_irb_seat_ids`, `effective_at` |
| `EvidenceFloorHashInputV1` | `final_package_root`, `evidence_graph_root`, sorted `independent_evidence_classes` |
| `EstopActionDispositionSetHashInputV1` | `tenant_id`, `protocol_id`, `protocol_version_hash`, `final_package_root`, `event_id`, `event_hash`, `scope_hash`, ordered verified vote signed-payload hashes, `verified_at` |
| `EstopProviderApprovalSetHashInputV1` | row-8 `action_binding_hash`, row-21 `verified_vote_set_hash`, sorted active/approve provider classes, sorted approving seat IDs, `computed_at` |
| `PendingEstopDecisionHashInputV1` | all eight materialization semantics, `event_id`, `event_hash`, `protocol_version_hash`, `final_package_root` |
| `EstopReferenceHashInputV1` | `estop_id`, `event_id`, `event_hash`, `protocol_version_hash`, `final_package_root`, `scope_hash`, row-23 `authorization_hash`, execution `receipt_hash`, `receipt_sequence`, `fired_at` |
| `CapaOpenDecisionHashInputV1` | `capa_id`, `event_id`, `scope_hash`, `protocol_version_hash`, `final_package_root`, `source_estop_id`, `owner_did`, row-25 `owner_authorization_hash`, `opened_at` |
| `CapaCompletionHashInputV1` | `capa_id`, `event_id`, `scope_hash`, `final_package_root`, `source_estop_id`, `owner_did`, row-25 `owner_authorization_hash`, sorted corrective/preventive action hashes, `completion_evidence_hash`, `receipt_hash`, `receipt_sequence`, `completed_at` |
| `RecurrenceResultHashInputV1` | `estop_id`, `event_id`, `capa_id`, `final_package_root`, `authority_hash`, `signer_did`, `test_suite_hash`, row-28 signed payload hash, `receipt_hash`, `receipt_sequence`, `passed`, `verified_at` |
| `SystemicLearningDecisionHashInputV1` | `record_id`, `source_event_id`, `event_hash`, `final_package_root`, exact `record_hash`, `authority_effect`, `prepared_at` |
| `EventCloseDecisionHashInputV1` | `event_id`, `event_hash`, `scope_hash`, `final_package_root`, row-30 `systemic_learning_hash`, row-31 `event_close_target_hash`, `council_proof_hash`, `ai_irb_proof_hash`, `authorized_at` |
| `HumanAarRcaHashInputV1` | `attestation_id`, `estop_id`, `event_id`, `stopped_scope_hash`, `stopped_package_root`, `investigator_did`, row-34 human classification hash, row-36 designation hash, `aar_hash`, `rca_hash`, row-37 signed payload hash, `attested_at` |
| `StopContinuationHashInputV1` | every `VerifiedStopContinuationV1` field in declaration order except `continuation_hash` |
| `ResetDecisionHashInputV1` | row-40 `reset_target_hash`, `reset_id`, `estop_id`, `event_id`, `stopped_scope_hash`, `stopped_package_root`, `successor_version_hash`, `successor_package_root`, row-41 continuation hash, row-38 AAR/RCA hash, row-27 CAPA completion hash, row-29 recurrence hash, Council proof hash, AI-IRB proof hash, row-39 Chair authorization hash, `authorized_at` |

Rows whose canonical value is a public target, signing payload, raw complete
statement, or complete signed designation hash that type directly with all fields
shown in its exact interface. `ActionBindingV1` hashes its complete enum target;
`ClaimThresholdDefinitionV1` and `ProgressiveThresholdResultV1` hash their
complete visible fields. This inventory is enforced by authoritative-pointer
mutation tests: changing any listed leaf changes the hash or fails validation.

### Independent known-answer vectors

`tools/cross-impl-test/vectors/df_protocol_authority_v1.json` contains exactly
42 records in registry order. Each record contains `variant`, `domain`, the full
integer-only typed input as transport data, canonical CBOR hex, BLAKE3 hex, and,
for the seven signed payloads plus D9 receipt, fixed public key, signature, and
verification result. Rust and TypeScript independently reconstruct the typed
input, emit canonical CBOR, hash it, and verify fixed signatures. Neither runner
may read `canonical_cbor_hex`, `blake3_hex`, or the other runner's output as its
actual result. A unit runner must reject a missing record, duplicated variant,
wrong domain, forged expected hash, expected-derived actual, reordered map,
changed signed field, or signature from a neighboring domain.

Exact vector commands:

```bash
cargo test -p exochain-decision-forum --lib protocol::cross_impl_tests::slice3_authority_known_answers -- --exact --nocapture
npm --prefix tools/cross-impl-test test -- --test-name-pattern='slice 3 authority known answers'
./tools/cross-impl-test/compare_unit_test.sh
./tools/cross-impl-test/compare.sh --verbose
```

Expected RED is a missing domain/actual, canonical bytes mismatch, or exact
hash/signature mismatch. GREEN requires 42 Rust actuals and 42 TypeScript
actuals with byte-identical keys, CBOR, hashes, and signature verdicts.

## Immutable trust bootstrap retained from Wave 3

Gatekeeper owns only upstream `exo_core`/Gatekeeper types. It imports no
`decision_forum` or Slice 2 codec type. Preserve private fields, a non-Clone,
non-Serialize, non-publicly constructible
`DecisionForumOperatorBootstrapCapabilityV1`, an ordinary `Kernel::new` with no
Decision Forum roots, and a deterministic issuer only under `cfg(test)` or the
nondefault `decision-forum-test-fixtures` feature. Decision Forum enables that
feature only in dev-dependencies.

```rust
impl Kernel {
    pub fn new_with_decision_forum_operator_bootstrap(
        constitution_corpus_bytes: &[u8],
        invariants: InvariantSet,
        bootstrap: DecisionForumOperatorBootstrapCapabilityV1,
        canonical_manifest_cbor: &[u8],
        manifest_signature: &Signature,
        configured_at: Timestamp,
    ) -> Result<Self, GatekeeperError>;

    pub fn decision_forum_root_binding(
        &self,
    ) -> Result<VerifiedDecisionForumRootBindingV1, GatekeeperError>;

    pub fn verify_decision_forum_root_signature(
        &self,
        binding: &VerifiedDecisionForumRootBindingV1,
        root_class: DecisionForumRootClassV1,
        signer_did: &Did,
        signing_key_id: Hash256,
        payload: &[u8],
        signature: &Signature,
        verified_at: Timestamp,
    ) -> Result<VerifiedDecisionForumRootSignatureV1, GatekeeperError>;
}
```

The constructor consumes the capability and validates manifest digest,
manifest signature, bootstrap key ID, immutable policy hash, constitution hash,
tenant, validity interval, unique root classes, DIDs, and key IDs. The narrow
verifier returns no key, resolver, root map, iterator, or generic closure. A
self-consistent attacker manifest, key, corpus, roots, and downstream signatures
still fail against both the ordinary kernel and the immutable legitimate
capability.

## Derivable package, Chair, and stop-continuation witnesses

### Package-bound authority facts

These opaque types have private fields, no `Serialize`/`Deserialize`, and no
public or production-test constructor:

```rust
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedPackageBoundaryV1 {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: ProtocolHash256,
    final_package_root: ProtocolHash256,
    prior_version_hash: Option<ProtocolHash256>,
    constitution_hash: ProtocolHash256,
    prior_execution: Option<VerifiedPriorExecutionCommitmentV1>,
    chair_did: Did,
    boundary_hash: ProtocolHash256,
}

#[derive(Debug, PartialEq, Eq)]
struct VerifiedPriorExecutionCommitmentV1 {
    prior_protocol_version_hash: ProtocolHash256,
    authorized_package_root: ProtocolHash256,
    previous_chain_root: ProtocolHash256,
    predecessor_terminal_receipt_hash: ProtocolHash256,
    predecessor_terminal_sequence: u64,
    first_sequence: u64,
    chain_root: ProtocolHash256,
    terminal_receipt_hash: ProtocolHash256,
    terminal_sequence: u64,
    receipt_count: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedPackageChairAuthorityV1 {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: ProtocolHash256,
    final_package_root: ProtocolHash256,
    chair_did: Did,
    chair_signing_key_id: ProtocolHash256,
    chair_authority_chain_hash: ProtocolHash256,
    package_boundary_hash: ProtocolHash256,
    authority_hash: ProtocolHash256,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedSuccessorPackageBoundaryV1 {
    tenant_id: String,
    protocol_id: String,
    predecessor_version_hash: ProtocolHash256,
    predecessor_package_root: ProtocolHash256,
    successor_version_hash: ProtocolHash256,
    successor_package_root: ProtocolHash256,
    constitution_hash: ProtocolHash256,
    successor_prior_execution: VerifiedPriorExecutionCommitmentV1,
    successor_boundary_hash: ProtocolHash256,
}

pub fn verify_package_boundary(
    package: &PeerReviewedProtocolPackageV1,
    root: &VerifiedPackageRoot,
) -> Result<VerifiedPackageBoundaryV1, ProtocolError>;

pub fn verify_package_chair_authority(
    boundary: &VerifiedPackageBoundaryV1,
    chair: &VerifiedNonSeatAuthorityV1,
) -> Result<VerifiedPackageChairAuthorityV1, ProtocolError>;

pub fn verify_successor_package_boundary(
    predecessor: &VerifiedPackageBoundaryV1,
    successor: &VerifiedPackageBoundaryV1,
) -> Result<VerifiedSuccessorPackageBoundaryV1, ProtocolError>;
```

`verify_package_boundary` recomputes the exact package root, protocol-version
hash, constitution hash, prior-version link, full prior-execution reference,
and Chair DID from the supplied package and rejects any mismatch with the opaque
root. `verify_package_chair_authority` requires the exact package Chair DID,
signing key ID, authority-chain hash, tenant, protocol, root manifest, and
`ChairInterventionV1` scope in an immutable-operator-rooted
`VerifiedNonSeatAuthorityV1`. `verify_successor_package_boundary` requires same
tenant/protocol/constitution, distinct roots and versions, exact immediate
`prior_version_hash`, and a present prior-execution commitment whose version and
authorized package root equal the predecessor. It retains the entire prior-chain
reference for the history proof; it does not accept a caller hash alias.

### Ordered receipt history and exact stop membership

Extend the existing Slice 2 receipt owners, not a parallel ledger:

```rust
#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedExecutionReceiptFactV1 {
    pub(super) receipt_hash: ProtocolHash256,
    pub(super) sequence: u64,
    pub(super) previous_receipt_hash: ProtocolHash256,
    pub(super) receipt_kind: ProtocolExecutionReceiptKind,
    pub(super) payload_hash: ProtocolHash256,
    pub(super) protocol_version_hash: ProtocolHash256,
    pub(super) authorized_package_root: ProtocolHash256,
    pub(super) occurred_at: ProtocolHlc,
}

pub struct VerifiedExecutionHistory {
    head: VerifiedExecutionSegment,
    ordered_receipts: Vec<VerifiedExecutionReceiptFactV1>,
    receipt_ids: BTreeSet<ProtocolUuid>,
    idempotency_keys: BTreeSet<ProtocolHash256>,
    receipt_hashes: BTreeSet<ProtocolHash256>,
    segment_roots: BTreeSet<ProtocolHash256>,
}

pub struct VerifiedStopContinuationV1 {
    tenant_id: String,
    protocol_id: String,
    estop_id: ProtocolUuid,
    event_id: ProtocolUuid,
    stopped_scope_hash: ProtocolHash256,
    stopped_package_root: ProtocolHash256,
    stopped_version_hash: ProtocolHash256,
    stop_authorization_hash: ProtocolHash256,
    stop_receipt_hash: ProtocolHash256,
    stop_receipt_sequence: u64,
    predecessor_history_chain_root: ProtocolHash256,
    predecessor_terminal_receipt_hash: ProtocolHash256,
    predecessor_terminal_sequence: u64,
    successor_version_hash: ProtocolHash256,
    successor_package_root: ProtocolHash256,
    successor_prior_execution_chain_root: ProtocolHash256,
    constitution_hash: ProtocolHash256,
    continuation_hash: ProtocolHash256,
}

impl VerifiedExecutionHistory {
    pub(crate) fn verify_stop_continuation(
        &self,
        stop: &VerifiedEstopReferenceV1,
        predecessor: &VerifiedPackageBoundaryV1,
        successor: &VerifiedSuccessorPackageBoundaryV1,
    ) -> Result<VerifiedStopContinuationV1, ProtocolError>;
}
```

`verify_execution_receipt_segment` derives every ordered fact from a verified
signed receipt. History construction concatenates only contiguous verified
segments and rechecks sequence, previous-receipt link, previous-chain root,
terminal hash/sequence, tenant, protocol, and replay/fork sets. Stop continuation
then proves all of the following from retained facts:

- predecessor boundary tenant/protocol/version/root equals the stopped scope;
- exactly one ordered receipt equals the stop receipt hash and sequence;
- that receipt has kind `Estop`, payload hash equal to the stop authorization
  hash, stopped version/root, and a valid link in this same history;
- the stop receipt precedes or equals the retained terminal receipt;
- successor boundary names this exact predecessor version/root and unchanged
  constitution;
- the successor's complete prior-execution commitment equals this history's
  previous root, first sequence, chain root, terminal hash/sequence, and count;
  and
- the successor is distinct and immediately follows the stopped version.

A valid successor root with stale prior-chain data, changed constitution,
different predecessor version, unrelated stop history, omitted stop, broken
link/sequence, fork, replay, or cross-tenant data returns the contextual existing
receipt error or `StopContinuationMismatch`. `continuation_hash` is row 41 over
all result fields except itself.

## Exact signature payloads and human-proof producers

Extend `AuthorityScope` exactly once with `ProtocolActionDispositionV1`,
`HumanInvestigatorDesignationV1`, `HumanAarRcaAttestationV1`, `CapaOpenV1`,
`CapaCompletionV1`, `EventCloseV1`, `ChairResetAuthorizationV1`, and
`RecurrenceResultV1`. Extend `SignedPayloadTarget` exactly once with
`ProtocolActionDispositionV1`, `ChairDesignationV1`,
`HumanClassificationV1`, `HumanAarRcaAttestationV1`,
`CapaOwnerActionV1`, `ChairResetAuthorizationV1`, and
`RecurrenceResultV1`. Add exactly these seven signature envelopes:

```rust
signature_envelope!(ProtocolActionDispositionSignatureV1);
signature_envelope!(ChairDesignationSignatureV1);
signature_envelope!(HumanClassificationSignatureV1);
signature_envelope!(HumanAarRcaSignatureV1);
signature_envelope!(CapaOwnerActionSignatureV1);
signature_envelope!(ChairResetSignatureV1);
signature_envelope!(RecurrenceResultSignatureV1);
```

The seven canonical signing payloads contain every corresponding raw signed
record field except `signature`. The exact payloads newly critical to RESET are:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HumanClassificationSigningPayloadV1 {
    pub statement_id: ProtocolUuid,
    pub subject_did: Did,
    pub subject_signing_key_id: ProtocolHash256,
    pub classification: HumanSignerKind,
    pub valid_from: ProtocolHlc,
    pub valid_until: ProtocolHlc,
    pub issuer_did: Did,
    pub issuer_signing_key_id: ProtocolHash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChairInvestigatorDesignationSigningPayloadV1 {
    pub designation_id: ProtocolUuid,
    pub chair_did: Did,
    pub chair_signing_key_id: ProtocolHash256,
    pub investigator_did: Did,
    pub investigator_signing_key_id: ProtocolHash256,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub stopped_scope_hash: ProtocolHash256,
    pub stopped_package_root: ProtocolHash256,
    pub signed_at: ProtocolHlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HumanAarRcaSigningPayloadV1 {
    pub attestation_id: ProtocolUuid,
    pub investigator_did: Did,
    pub investigator_signing_key_id: ProtocolHash256,
    pub designation_hash: ProtocolHash256,
    pub human_classification_hash: ProtocolHash256,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub stopped_scope_hash: ProtocolHash256,
    pub stopped_package_root: ProtocolHash256,
    pub aar_hash: ProtocolHash256,
    pub rca_hash: ProtocolHash256,
    pub attested_at: ProtocolHlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChairResetAuthorizationSigningPayloadV1 {
    pub reset_id: ProtocolUuid,
    pub chair_did: Did,
    pub chair_signing_key_id: ProtocolHash256,
    pub reset_target_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
}
```

`ProtocolActionDispositionSigningPayloadV1` is the complete
`ProtocolActionDispositionV1` excluding `signature` and including the complete
`ActionBindingV1`. `CapaOwnerActionSigningPayloadV1` is the complete
`SignedCapaOwnerActionV1` excluding `signature`.
`RecurrenceResultSigningPayloadV1` is the complete
`SignedRecurrenceResultV1` excluding `signature`. Each implements
`From<&SignedRecord>` by direct field copy and hashes only with its registry row.

Human schema labels do not prove humanity. The exact raw and opaque types are:

```rust
pub struct HumanClassificationStatementV1 {
    pub statement_id: ProtocolUuid,
    pub subject_did: Did,
    pub subject_signing_key_id: ProtocolHash256,
    pub classification: HumanSignerKind,
    pub valid_from: ProtocolHlc,
    pub valid_until: ProtocolHlc,
    pub issuer_did: Did,
    pub issuer_signing_key_id: ProtocolHash256,
    pub signature: HumanClassificationSignatureV1,
}

pub struct HumanInvestigatorDesignationV1 {
    pub designation_id: ProtocolUuid,
    pub chair_did: Did,
    pub chair_signing_key_id: ProtocolHash256,
    pub investigator_did: Did,
    pub investigator_signing_key_id: ProtocolHash256,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub stopped_scope_hash: ProtocolHash256,
    pub stopped_package_root: ProtocolHash256,
    pub signed_at: ProtocolHlc,
    pub signature: ChairDesignationSignatureV1,
}

pub struct SignedHumanAarRcaEvidenceV1 {
    pub attestation_id: ProtocolUuid,
    pub investigator_did: Did,
    pub investigator_signing_key_id: ProtocolHash256,
    pub designation_hash: ProtocolHash256,
    pub human_classification_hash: ProtocolHash256,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub stopped_scope_hash: ProtocolHash256,
    pub stopped_package_root: ProtocolHash256,
    pub aar_hash: ProtocolHash256,
    pub rca_hash: ProtocolHash256,
    pub attested_at: ProtocolHlc,
    pub signature: HumanAarRcaSignatureV1,
}

pub struct VerifiedHumanClassificationV1 {
    subject_did: Did,
    subject_signing_key_id: ProtocolHash256,
    valid_from: ProtocolHlc,
    valid_until: ProtocolHlc,
    issuer_did: Did,
    root_manifest_hash: ProtocolHash256,
    statement_hash: ProtocolHash256,
}

pub struct VerifiedChairHumanAuthorityV1 {
    package_chair: VerifiedPackageChairAuthorityV1,
    human: VerifiedHumanClassificationV1,
}

pub struct VerifiedHumanInvestigatorAuthorityV1 {
    investigator: VerifiedNonSeatAuthorityV1,
    human: VerifiedHumanClassificationV1,
    designation_hash: ProtocolHash256,
    stopped_package_root: ProtocolHash256,
    stopped_scope_hash: ProtocolHash256,
}

impl<'a> AuthorityVerifierV1<'a> {
    pub fn verify_human_classification(
        &self,
        subject: &VerifiedNonSeatAuthorityV1,
        statement: &HumanClassificationStatementV1,
        verified_at: ProtocolHlc,
    ) -> Result<VerifiedHumanClassificationV1, ProtocolError>;

    pub fn verify_chair_human_authority(
        &self,
        package_chair: VerifiedPackageChairAuthorityV1,
        chair_authority: &VerifiedNonSeatAuthorityV1,
        classification: VerifiedHumanClassificationV1,
        verified_at: ProtocolHlc,
    ) -> Result<VerifiedChairHumanAuthorityV1, ProtocolError>;

    pub fn verify_human_investigator_authority(
        &self,
        stop: &VerifiedEstopReferenceV1,
        chair: &VerifiedChairHumanAuthorityV1,
        investigator: VerifiedNonSeatAuthorityV1,
        classification: VerifiedHumanClassificationV1,
        designation: &HumanInvestigatorDesignationV1,
        verified_at: ProtocolHlc,
    ) -> Result<VerifiedHumanInvestigatorAuthorityV1, ProtocolError>;
}

pub fn verify_human_aar_rca(
    stop: &VerifiedEstopReferenceV1,
    investigator: &VerifiedHumanInvestigatorAuthorityV1,
    evidence: &SignedHumanAarRcaEvidenceV1,
) -> Result<VerifiedHumanAarRcaV1, ProtocolError>;
```

`verify_human_classification` verifies the row-33 payload hash/signature through
the Gatekeeper `HumanClassification` root, exact issuer/key/root manifest,
subject DID/key from independently rooted non-seat identity/authority facts,
`classification == HumanSignerKind::Human`, and an interval containing
`verified_at`. `verify_chair_human_authority` requires the same subject DID/key
as the exact package Chair and a `ChairResetAuthorizationV1` authority scope.
`verify_human_investigator_authority` requires human classification for the
exact investigator DID/key, `HumanAarRcaAttestationV1` authority, and a Chair
signature over the row-35 payload for the exact stop/scope/root. Values are
consumed into composite proofs so they cannot be rebound.

Self-signed classification, AI DID labeled human, expired classification,
issuer/root/key mismatch, non-package Chair, undesignated investigator,
different stop/scope/root, changed designation, or neighboring-domain signature
fails with an exact `HumanClassificationInvalid`, `ProofBindingMismatch`, or
`ResetBindingMismatch`.

## Verified monitoring, exact Chair routing, and events

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum IntegerComparatorV1 {
    GreaterThan,
    GreaterThanOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimThresholdDefinitionV1 {
    pub claim_hash: ProtocolHash256,
    pub comparator: IntegerComparatorV1,
    pub threshold_value: u64,
    pub unit_domain: String,
    pub evidence_domain: String,
}

pub struct VerifiedMonitoringPlanV1 {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: ProtocolHash256,
    final_package_root: ProtocolHash256,
    package_boundary_hash: ProtocolHash256,
    monitoring_plan_hash: ProtocolHash256,
    thresholds_by_claim: BTreeMap<ProtocolHash256, ClaimThresholdDefinitionV1>,
    chair_did: Did,
    chair_authority_hash: ProtocolHash256,
    reporting_destinations: BTreeSet<String>,
    event_payload_type_domains: BTreeSet<String>,
    max_iterations: u8,
    repeat_failure_limit: u8,
}

pub fn verify_monitoring_plan(
    package: &PeerReviewedProtocolPackageV1,
    root: &VerifiedPackageRoot,
    boundary: &VerifiedPackageBoundaryV1,
    chair: &VerifiedPackageChairAuthorityV1,
    threshold_catalog: &[ClaimThresholdDefinitionV1],
) -> Result<VerifiedMonitoringPlanV1, ProtocolError>;
```

The function recomputes the package/root and requires the same boundary and
Chair proof. It rejects the package if
`monitoring_plan.escalation_destination != protocol_identity.chair_did`.
Every `claim_thresholds` reference must have kind `df_claim_threshold_v1`, media
type `application/vnd.exochain.df-claim-threshold-v1+cbor`, and row-6 hash equal
to exactly one catalog entry. Additions, omissions, duplicates, claim
collisions, changed comparator/value/unit/evidence domain, wrong package,
cross-root replay, non-Chair escalation DID, and Chair-authority mismatch fail.

```rust
pub struct ObservedClaimValueV1 {
    pub claim_hash: ProtocolHash256,
    pub observed_evidence_hash: ProtocolHash256,
    pub observed_value: u64,
}

pub struct ProgressiveThresholdResultV1 {
    pub claim_hash: ProtocolHash256,
    pub comparator: IntegerComparatorV1,
    pub threshold_value: u64,
    pub observed_evidence_hash: ProtocolHash256,
    pub observed_value: u64,
    pub satisfied: bool,
}

pub struct ProgressiveEventAuthorizationTargetV1 {
    pub event_id: ProtocolUuid,
    pub event_hash: ProtocolHash256,
    pub scope_hash: ProtocolHash256,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub monitoring_plan_hash: ProtocolHash256,
    pub threshold_definition_hash: ProtocolHash256,
    pub observed_evidence_hash: ProtocolHash256,
    pub threshold_result_hash: ProtocolHash256,
}

pub struct VerifiedProgressiveEventDecisionV1 {
    event_id: ProtocolUuid,
    event_hash: ProtocolHash256,
    scope_hash: ProtocolHash256,
    final_package_root: ProtocolHash256,
    monitoring_plan_hash: ProtocolHash256,
    progressive_target_hash: ProtocolHash256,
    threshold_definition_hash: ProtocolHash256,
    observed_evidence_hash: ProtocolHash256,
    threshold_result_hash: ProtocolHash256,
    council_proof_hash: ProtocolHash256,
    ai_irb_proof_hash: ProtocolHash256,
    decision_hash: ProtocolHash256,
}

pub fn progressive_event_authorization_target(
    monitoring: &VerifiedMonitoringPlanV1,
    event: &VerifiedProtocolEventV1,
    observation: &ObservedClaimValueV1,
) -> Result<ProgressiveEventAuthorizationTargetV1, ProtocolError>;

pub fn evaluate_progressive_event(
    monitoring: &VerifiedMonitoringPlanV1,
    event: &VerifiedProtocolEventV1,
    target: &ProgressiveEventAuthorizationTargetV1,
    council: &VerifiedEligibleUnanimityDecisionV1,
    ai_irb: &VerifiedEligibleUnanimityDecisionV1,
) -> Result<VerifiedProgressiveEventDecisionV1, ProtocolError>;
```

The target builder looks up the retained threshold, performs the integer
comparison, hashes the complete threshold result with row 13, and hashes the
complete target with row 14. Evaluation requires both bodies to carry the exact
row-14 target in a `ProgressiveEventDisposition` action binding. Same event ID
with changed event bytes, same observation with changed threshold, changed
monitoring root, changed evidence, or a target signed for another package fails.

Adverse and AI-SDLC evaluators likewise require exact event-bound action
bindings. AI-SDLC always returns containment plus the complete Chair,
continuing-review, and mandatory-reporting union. No classifier may discard an
event.

## Action bindings, fixed unanimity, and phase promotion

`ProtocolAuthorityActionKindV1` has exactly:
`InitialAuthorization`, `MonitoringContinuation`,
`ProgressiveEventDisposition`, `AdverseEventDisposition`, `Estop`, `CapaOpen`,
`CapaComplete`, `EventClose`, `Reset`, and `PhasePromotion`.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ProtocolAuthorityActionTargetV1 {
    InitialAuthorization { authorization_target_hash: ProtocolHash256 },
    Monitoring { event_id: ProtocolUuid, event_hash: ProtocolHash256 },
    Progressive {
        event_id: ProtocolUuid,
        event_hash: ProtocolHash256,
        monitoring_plan_hash: ProtocolHash256,
        threshold_definition_hash: ProtocolHash256,
        threshold_result_hash: ProtocolHash256,
        progressive_target_hash: ProtocolHash256,
    },
    Adverse { event_id: ProtocolUuid, event_hash: ProtocolHash256 },
    Estop { estop_id: ProtocolUuid, event_id: ProtocolUuid, event_hash: ProtocolHash256 },
    Capa { capa_id: ProtocolUuid, event_id: ProtocolUuid, capa_hash: ProtocolHash256 },
    EventClose {
        event_id: ProtocolUuid,
        event_hash: ProtocolHash256,
        systemic_learning_hash: ProtocolHash256,
        event_close_target_hash: ProtocolHash256,
    },
    Reset { reset_id: ProtocolUuid, reset_target_hash: ProtocolHash256 },
    PhasePromotion {
        promotion_id: ProtocolUuid,
        event_id: ProtocolUuid,
        event_hash: ProtocolHash256,
        progressive_decision_hash: ProtocolHash256,
        from_phase_hash: ProtocolHash256,
        to_phase_hash: ProtocolHash256,
        envelope_hash: ProtocolHash256,
        promotion_target_hash: ProtocolHash256,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionBindingV1 {
    pub tenant_id: String,
    pub protocol_id: String,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub action_kind: ProtocolAuthorityActionKindV1,
    pub scope_hash: ProtocolHash256,
    pub target: ProtocolAuthorityActionTargetV1,
    pub review_bundle_hash: ProtocolHash256,
    pub eligible_set_hash: ProtocolHash256,
    pub evidence_graph_root: ProtocolHash256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolActionDispositionV1 {
    pub disposition_id: ProtocolUuid,
    pub seat_id: Did,
    pub seat_kind: SeatKind,
    pub provider_class: ProviderClass,
    pub choice: DispositionChoice,
    pub binding: ActionBindingV1,
    pub seat_attestation_hash: ProtocolHash256,
    pub context_manifest_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
    pub signature: ProtocolActionDispositionSignatureV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolActionDispositionSigningPayloadV1 {
    pub disposition_id: ProtocolUuid,
    pub seat_id: Did,
    pub seat_kind: SeatKind,
    pub provider_class: ProviderClass,
    pub choice: DispositionChoice,
    pub binding: ActionBindingV1,
    pub seat_attestation_hash: ProtocolHash256,
    pub context_manifest_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
}

impl VerifiedPackageTrustRegistryV1 {
    pub(crate) fn verify_protocol_action_disposition(
        &self,
        root: &VerifiedPackageRoot,
        vote: &ProtocolActionDispositionV1,
    ) -> Result<VerifiedActionDispositionV1, ProtocolError>;
}

impl<'a> AuthorityVerifierV1<'a> {
    pub fn evaluate_eligible_unanimity(
        &self,
        root: &VerifiedPackageRoot,
        trust: &VerifiedPackageTrustRegistryV1,
        binding: &ActionBindingV1,
        votes: &[ProtocolActionDispositionV1],
        computed_at: ProtocolHlc,
    ) -> Result<VerifiedEligibleUnanimityDecisionV1, ProtocolError>;
}
```

No public free action verifier and no second receiver exist. The evaluator
structurally verifies one signed `Approve`, `Reject`, or `Abstain` from every
fixed seat, rejects duplicate/missing/wrong-body seats, recomputes the exact
approval set and all four `QuorumResult` variants, then enforces five of five,
all four providers, and both independent evidence classes. The row-10 decision
hash covers the complete binding, fixed eligible/approve sets, provider/evidence
sets, counts, result, and HLC.

```rust
pub struct PhasePromotionAuthorizationTargetV1 {
    pub promotion_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub event_hash: ProtocolHash256,
    pub progressive_decision_hash: ProtocolHash256,
    pub scope_hash: ProtocolHash256,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub from_phase_hash: ProtocolHash256,
    pub to_phase_hash: ProtocolHash256,
    pub envelope_hash: ProtocolHash256,
}

pub fn phase_promotion_authorization_target(
    promotion_id: ProtocolUuid,
    envelope: &VerifiedEnvelopePhaseLadderV1,
    current: &VerifiedProtocolPhaseStateV1,
    progressive: &VerifiedProgressiveEventDecisionV1,
    request: &PhasePromotionRequestV1,
) -> Result<PhasePromotionAuthorizationTargetV1, ProtocolError>;

pub fn evaluate_phase_promotion(
    envelope: &VerifiedEnvelopePhaseLadderV1,
    current: &VerifiedProtocolPhaseStateV1,
    progressive: &VerifiedProgressiveEventDecisionV1,
    request: &PhasePromotionRequestV1,
    target: &PhasePromotionAuthorizationTargetV1,
    council: &VerifiedEligibleUnanimityDecisionV1,
    ai_irb: &VerifiedEligibleUnanimityDecisionV1,
    promoted_at: ProtocolHlc,
) -> Result<(PendingPhasePromotionDecisionV1, PendingNotificationRequirementV1), ProtocolError>;
```

The target builder requires the immediate next distinct phase and field-for-
field equality of permitted actions, systems, tenants, datasets, actor classes,
every resource ceiling, risk ceiling, start/end HLC, and ordered phase ladder.
It commits the exact row-15 progressive decision hash and hashes the promotion
target with row 17. Both body decisions must contain the exact target fields and
row-17 hash. Same phase with another progressive proof, same event ID with
changed event, skipped/reordered phase, cross-monitoring replay, or any envelope
change fails.

## Typed notifications use only the verified package Chair

```rust
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotificationDestinationV1 {
    Chair(Did),
    ContinuingReview { protocol_id: String },
    MandatoryReporting(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationCauseV1 {
    AuthorizationDissent,
    MonitoringDissent,
    AdverseEvent,
    AiSdlcTransgression,
    Estop,
    PhasePromotion,
}

pub struct PendingNotificationRequirementV1 {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: ProtocolHash256,
    final_package_root: ProtocolHash256,
    subject: NotificationSubjectV1,
    scope_hash: ProtocolHash256,
    cause: NotificationCauseV1,
    verified_chair_authority_hash: ProtocolHash256,
    required_destinations: BTreeSet<NotificationDestinationV1>,
    required_at: ProtocolHlc,
    requirement_hash: ProtocolHash256,
}

impl PendingNotificationRequirementV1 {
    pub fn required_destinations(&self) -> &BTreeSet<NotificationDestinationV1>;
    pub fn validate_destination_coverage(
        &self,
        observed: &BTreeSet<NotificationDestinationV1>,
    ) -> Result<(), ProtocolError>;
}
```

Every producer receives `&VerifiedMonitoringPlanV1`; no producer accepts a raw
Chair DID. `NotificationDestinationV1::Chair` is constructed only from the
opaque plan's retained package Chair. Authorization dissent returns Chair;
monitoring dissent returns Chair plus continuing review; adverse returns Chair
plus continuing review; AI-SDLC and E-STOP return Chair plus continuing review
plus every retained reporting destination; promotion returns Chair. A valid
package with `monitoring_plan.escalation_destination` set to a different valid
DID fails before any requirement exists. Delivery success or failure is Slice 4
evidence and never removes another destination.

## CAPA, recurrence, learning, and separate event close

Preserve Wave 3's signed owner open/complete separation. `SignedCapaOwnerActionV1`
binds action ID/kind, CAPA/event/optional E-STOP, scope, version, package root,
owner DID, exact `CapaRecord` row-25 hash, HLC, and row-25 signature.
`verify_capa_owner_action` requires independently rooted exact `CapaOpenV1` or
`CapaCompletionV1` scope before `open_capa_for_event` or
`verify_capa_completion` can run. Receipt membership proves provenance but does
not substitute for owner authorization.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedCapaOwnerActionV1 {
    pub action_id: ProtocolUuid,
    pub action_kind: CapaOwnerActionKindV1,
    pub capa_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub source_estop_id: Option<ProtocolUuid>,
    pub scope_hash: ProtocolHash256,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub owner_did: Did,
    pub capa_record_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
    pub signature: CapaOwnerActionSignatureV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapaOwnerActionSigningPayloadV1 {
    pub action_id: ProtocolUuid,
    pub action_kind: CapaOwnerActionKindV1,
    pub capa_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub source_estop_id: Option<ProtocolUuid>,
    pub scope_hash: ProtocolHash256,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub owner_did: Did,
    pub capa_record_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedRecurrenceResultV1 {
    pub recurrence_id: ProtocolUuid,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub capa_id: ProtocolUuid,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub test_suite_hash: ProtocolHash256,
    pub result_evidence_hash: ProtocolHash256,
    pub outcome: RecurrenceOutcomeV1,
    pub signer_did: Did,
    pub signed_at: ProtocolHlc,
    pub signature: RecurrenceResultSignatureV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecurrenceResultSigningPayloadV1 {
    pub recurrence_id: ProtocolUuid,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub capa_id: ProtocolUuid,
    pub protocol_version_hash: ProtocolHash256,
    pub final_package_root: ProtocolHash256,
    pub test_suite_hash: ProtocolHash256,
    pub result_evidence_hash: ProtocolHash256,
    pub outcome: RecurrenceOutcomeV1,
    pub signer_did: Did,
    pub signed_at: ProtocolHlc,
}

pub fn verify_capa_owner_action(
    root: &VerifiedPackageRoot,
    owner: &VerifiedNonSeatAuthorityV1,
    action: &SignedCapaOwnerActionV1,
) -> Result<VerifiedCapaOwnerActionV1, ProtocolError>;

pub fn open_capa_for_event(
    event: &VerifiedProtocolEventV1,
    authorization: &VerifiedCapaOwnerActionV1,
) -> Result<PendingCapaOpenDecisionV1, ProtocolError>;

pub fn verify_capa_completion(
    event: &VerifiedProtocolEventV1,
    opened: &PendingCapaOpenDecisionV1,
    authorization: &VerifiedCapaOwnerActionV1,
    record: &CapaRecord,
    receipt: &VerifiedExecutionReceiptReferenceV1,
) -> Result<VerifiedCapaCompletionV1, ProtocolError>;

pub fn verify_recurrence_authority(
    authority: &VerifiedNonSeatAuthorityV1,
) -> Result<VerifiedRecurrenceAuthorityV1, ProtocolError>;

pub fn verify_recurrence_result(
    authority: &VerifiedRecurrenceAuthorityV1,
    stop: &VerifiedEstopReferenceV1,
    capa: &VerifiedCapaCompletionV1,
    evidence: &SignedRecurrenceResultV1,
    receipt: &VerifiedExecutionReceiptReferenceV1,
) -> Result<VerifiedRecurrenceResultV1, ProtocolError>;

pub fn prepare_systemic_learning(
    event: &VerifiedProtocolEventV1,
    capa: Option<&VerifiedCapaCompletionV1>,
    recurrence: Option<&VerifiedRecurrenceResultV1>,
    record: &SystemicLearningRecord,
    prepared_at: ProtocolHlc,
) -> Result<PendingSystemicLearningDecisionV1, ProtocolError>;

pub fn authorize_event_close(
    event: &VerifiedProtocolEventV1,
    learning: &PendingSystemicLearningDecisionV1,
    council: &VerifiedEligibleUnanimityDecisionV1,
    ai_irb: &VerifiedEligibleUnanimityDecisionV1,
    authorized_at: ProtocolHlc,
) -> Result<VerifiedEventCloseDecisionV1, ProtocolError>;
```

Recurrence requires a row-28 signature from independently rooted
`RecurrenceResultV1` authority, exact stop/event/CAPA/root/test suite, a passed
outcome, and exact receipt membership. Learning always reports
`grants_event_close() == false`. Event close uses a row-31 target containing the
event ID/hash, scope, package root, and row-30 learning hash; both bodies sign
that target before row-32 decision derivation.

## E-STOP verification, exact arithmetic, and nine-field separation

Keep the materialized type byte-for-byte at nine fields:

```rust
pub struct EstopAuthorization {
    pub estop_id: ProtocolUuid,
    pub scope_hash: ProtocolHash256,
    pub active_provider_classes: BTreeSet<ProviderClass>,
    pub approve_provider_classes: BTreeSet<ProviderClass>,
    pub required_provider_class_count: u8,
    pub independent_evidence_classes: BTreeSet<IndependentEvidenceClass>,
    pub threshold_result: EstopThresholdResult,
    pub fired_at: ProtocolHlc,
    pub receipt_root: ProtocolHash256,
}

fn checked_two_thirds_ceiling(active: usize) -> Result<u8, ProtocolError> {
    if active == 0 {
        return Err(ProtocolError::EmptyProviderDenominator);
    }
    let doubled = active.checked_mul(2).ok_or(ProtocolError::IntegerOverflow {
        operation: "2 * active providers",
    })?;
    let adjusted = doubled.checked_add(2).ok_or(ProtocolError::IntegerOverflow {
        operation: "ceil numerator",
    })?;
    let required = adjusted.checked_div(3).ok_or(ProtocolError::IntegerOverflow {
        operation: "ceil denominator",
    })?;
    u8::try_from(required).map_err(|_| ProtocolError::IntegerOverflow {
        operation: "provider threshold u8",
    })
}
```

`PendingEstopDecisionV1` contains the first eight semantic fields plus exact
event/version/root bindings and no `receipt_root`. The exact APIs remain:

```rust
pub fn verify_estop_action_dispositions(
    root: &VerifiedPackageRoot,
    trust: &VerifiedPackageTrustRegistryV1,
    event: &VerifiedProtocolEventV1,
    roster: &VerifiedActiveRosterSnapshotV1,
    votes: &[ProtocolActionDispositionV1],
    verified_at: ProtocolHlc,
) -> Result<VerifiedEstopActionDispositionSetV1, ProtocolError>;

pub fn verify_estop_provider_approvals(
    event: &VerifiedProtocolEventV1,
    roster: &VerifiedActiveRosterSnapshotV1,
    verified_votes: &VerifiedEstopActionDispositionSetV1,
    computed_at: ProtocolHlc,
) -> Result<VerifiedEstopProviderApprovalSetV1, ProtocolError>;

pub fn evaluate_estop_threshold(
    estop_id: ProtocolUuid,
    monitoring: &VerifiedMonitoringPlanV1,
    event: &VerifiedProtocolEventV1,
    roster: &VerifiedActiveRosterSnapshotV1,
    evidence: &VerifiedEvidenceFloorV1,
    approvals: &VerifiedEstopProviderApprovalSetV1,
    fired_at: ProtocolHlc,
) -> Result<(PendingEstopDecisionV1, PendingNotificationRequirementV1), ProtocolError>;

pub fn verify_estop_reference(
    pending: &PendingEstopDecisionV1,
    record: &EstopAuthorization,
    receipt: &VerifiedExecutionReceiptReferenceV1,
) -> Result<VerifiedEstopReferenceV1, ProtocolError>;
```

The non-optional trust registry is verified before any provider is counted.
Runtime negatives use supplied but wrong tenant/package/root/roster/context/body/
event/scope/seat registries and votes. Absence is unrepresentable and tested by
the compile-fail contract in Gate 00. The verified provider set is not
`VerifiedEligibleUnanimityDecisionV1`.

## One exact RESET target shared by Council, AI-IRB, and Chair

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResetAuthorizationTargetV1 {
    pub reset_id: ProtocolUuid,
    pub tenant_id: String,
    pub protocol_id: String,
    pub estop_id: ProtocolUuid,
    pub event_id: ProtocolUuid,
    pub stopped_scope_hash: ProtocolHash256,
    pub stopped_version_hash: ProtocolHash256,
    pub stopped_package_root: ProtocolHash256,
    pub stop_authorization_hash: ProtocolHash256,
    pub stop_receipt_hash: ProtocolHash256,
    pub successor_version_hash: ProtocolHash256,
    pub successor_package_root: ProtocolHash256,
    pub successor_boundary_hash: ProtocolHash256,
    pub stop_continuation_hash: ProtocolHash256,
    pub investigator_did: Did,
    pub investigator_human_classification_hash: ProtocolHash256,
    pub investigator_designation_hash: ProtocolHash256,
    pub human_aar_rca_hash: ProtocolHash256,
    pub capa_completion_hash: ProtocolHash256,
    pub recurrence_result_hash: ProtocolHash256,
    pub council_eligible_set_hash: ProtocolHash256,
    pub ai_irb_eligible_set_hash: ProtocolHash256,
    pub chair_did: Did,
    pub chair_signing_key_id: ProtocolHash256,
    pub chair_human_classification_hash: ProtocolHash256,
    pub constitution_hash: ProtocolHash256,
}

pub struct ChairResetAuthorizationV1 {
    pub reset_id: ProtocolUuid,
    pub chair_did: Did,
    pub chair_signing_key_id: ProtocolHash256,
    pub reset_target_hash: ProtocolHash256,
    pub signed_at: ProtocolHlc,
    pub signature: ChairResetSignatureV1,
}

pub fn reset_authorization_target(
    reset_id: ProtocolUuid,
    stop: &VerifiedEstopReferenceV1,
    continuation: &VerifiedStopContinuationV1,
    successor: &VerifiedSuccessorPackageBoundaryV1,
    investigator: &VerifiedHumanInvestigatorAuthorityV1,
    human_aar_rca: &VerifiedHumanAarRcaV1,
    capa: &VerifiedCapaCompletionV1,
    recurrence: &VerifiedRecurrenceResultV1,
    council_eligible_set_hash: ProtocolHash256,
    ai_irb_eligible_set_hash: ProtocolHash256,
    chair: &VerifiedChairHumanAuthorityV1,
) -> Result<ResetAuthorizationTargetV1, ProtocolError>;

pub fn verify_chair_reset_authorization(
    target: &ResetAuthorizationTargetV1,
    chair: &VerifiedChairHumanAuthorityV1,
    authorization: &ChairResetAuthorizationV1,
) -> Result<VerifiedChairResetAuthorizationV1, ProtocolError>;

pub fn evaluate_reset(
    target: &ResetAuthorizationTargetV1,
    stop: &VerifiedEstopReferenceV1,
    continuation: &VerifiedStopContinuationV1,
    successor: &VerifiedSuccessorPackageBoundaryV1,
    investigator: &VerifiedHumanInvestigatorAuthorityV1,
    human_aar_rca: &VerifiedHumanAarRcaV1,
    capa: &VerifiedCapaCompletionV1,
    recurrence: &VerifiedRecurrenceResultV1,
    council: &VerifiedEligibleUnanimityDecisionV1,
    ai_irb: &VerifiedEligibleUnanimityDecisionV1,
    chair: &VerifiedChairResetAuthorizationV1,
    authorized_at: ProtocolHlc,
) -> Result<VerifiedResetDecisionV1, ProtocolError>;
```

`reset_authorization_target` derives every field from opaque operands except the
caller-supplied reset ID and the two eligible-set hashes, which must match the
fixed package registries when votes are evaluated. It hashes the complete target
with row 40. Council and AI-IRB each sign an `ActionBindingV1` whose target is
exactly `Reset { reset_id, reset_target_hash }`, whose scope equals the stopped
scope, whose package version/root equals the successor, and whose eligible-set
hash equals the corresponding target field. The Chair row-39 signature signs the
same row-40 hash. No proof hash is inserted into the target that would create a
signature cycle; body and Chair identity/eligible-set bindings are fixed inputs,
while the resulting three proof hashes are row-42 output fields.

`evaluate_reset` recomputes row 40 and compares every opaque operand. A
substitution of stop, receipt, successor, constitution, continuation, human
classification, designation, AAR, RCA, CAPA, recurrence, Council eligible set,
AI-IRB eligible set, or Chair identity/key after signatures returns
`ResetBindingMismatch`. Missing or failed semantic evidence returns
`ResetPrerequisite`. RESET cannot reuse the stopped package hash, erase the
event, change the Constitution, or exceed the successor package envelope.

## Exact D9 amendment and per-mutation errors

Amendment signatures continue to call the existing
`amendment_signature_message` and existing amendment mutation algorithm. The
separate receipt signs `D9Amendment1ReceiptSigningPayloadV1` with registry row 3
through the immutable `Ratification` root. The exact public verifier remains:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct D9Amendment1ReceiptSigningPayloadV1 {
    pub receipt_id: ProtocolUuid,
    pub predecessor_blake3: ProtocolHash256,
    pub amendment_blake3: ProtocolHash256,
    pub predecessor_corpus_hash: ProtocolHash256,
    pub resulting_corpus_hash: ProtocolHash256,
    pub resulting_version: u64,
    pub resulting_amendment_count: u32,
    pub quorum_hash: ProtocolHash256,
    pub verified_signer_set_hash: ProtocolHash256,
    pub ratified_at: ProtocolHlc,
    pub receipt_signer_did: Did,
    pub receipt_signing_key_id: ProtocolHash256,
}

pub fn verify_d9_amendment_1_ratification(
    verifier: &AuthorityVerifierV1<'_>,
    exact_predecessor_bytes: &[u8],
    exact_amendment_bytes: &[u8],
    predecessor_corpus: &ConstitutionCorpus,
    resulting_corpus: &ConstitutionCorpus,
    quorum: &ConstitutionQuorum,
    eligible_signers: &BTreeSet<Did>,
    signatures: &[(Did, Signature)],
    receipt: &SignedD9RatificationReceiptV1,
) -> Result<VerifiedD9Amendment1RatificationV1, ProtocolError>;
```

Freeze these exact test enums and tables; no aggregate mutation constant is
permitted:

```rust
#[derive(Clone, Copy)]
enum D9PublicMutation {
    AmendmentMarkdownByte,
    AmendmentHeadingByte,
    AmendmentStatusByte,
    PredecessorMarkdownByte,
    PredecessorCorpusHash,
    ResultingCorpusHash,
    ResultingVersion,
    ResultingAmendmentCount,
    QuorumHash,
    VerifiedSignerSetHash,
    RatifiedAt,
    AmendmentSignatureUsesReceiptDomain,
    ReceiptSignatureUsesAmendmentDomain,
}

const D9_PUBLIC_EXPECTED_FIELDS: &[(D9PublicMutation, &str)] = &[
    (D9PublicMutation::AmendmentMarkdownByte, "exact_markdown_blake3"),
    (D9PublicMutation::AmendmentHeadingByte, "exact_markdown_blake3"),
    (D9PublicMutation::AmendmentStatusByte, "exact_markdown_blake3"),
    (D9PublicMutation::PredecessorMarkdownByte, "exact_predecessor_blake3"),
    (D9PublicMutation::PredecessorCorpusHash, "predecessor_corpus_hash"),
    (D9PublicMutation::ResultingCorpusHash, "resulting_corpus_hash"),
    (D9PublicMutation::ResultingVersion, "resulting_version"),
    (D9PublicMutation::ResultingAmendmentCount, "resulting_amendment_count"),
    (D9PublicMutation::QuorumHash, "quorum_hash"),
    (D9PublicMutation::VerifiedSignerSetHash, "verified_signer_set_hash"),
    (D9PublicMutation::RatifiedAt, "ratified_at"),
    (D9PublicMutation::AmendmentSignatureUsesReceiptDomain, "amendment_signatures"),
    (D9PublicMutation::ReceiptSignatureUsesAmendmentDomain, "receipt_signature"),
];

#[derive(Clone, Copy)]
enum D9MappedArticleMutation { Id, Title, Tier, Status, TextHash }

const D9_MAPPING_EXPECTED_FIELDS: &[(D9MappedArticleMutation, &str)] = &[
    (D9MappedArticleMutation::Id, "article_mapping"),
    (D9MappedArticleMutation::Title, "article_mapping"),
    (D9MappedArticleMutation::Tier, "article_mapping"),
    (D9MappedArticleMutation::Status, "article_mapping"),
    (D9MappedArticleMutation::TextHash, "article_mapping"),
];
```

Public heading/status byte changes fail the BLAKE3 gate before UTF-8/article
mapping and therefore expect `exact_markdown_blake3`. A crate-internal unit test
directly mutates the already derived `Article` and calls the package-private
mapping comparator to reach `article_mapping`. Invalid UTF-8 is tested directly
against the package-private UTF-8 helper and expects `amendment_utf8`; it is not
misrepresented as a public verifier result. Existing-domain signatures reused
as receipt signatures and receipt-domain signatures reused as amendment
signatures fail.

## Exact error ownership

`GatekeeperError` owns the Wave 3 bootstrap/root variants:
`DecisionForumBootstrapRequired`, `DecisionForumBootstrapMismatch`,
`DecisionForumManifestSignatureInvalid`, `DecisionForumRootClassMissing`,
`DecisionForumRootSignatureInvalid`, and
`DecisionForumRootBindingMismatch`. Every mismatch carries exact field,
expected, and actual context where applicable.

`ProtocolError` owns these Slice 3 variants in addition to the frozen Slice 2
variants:

```rust
UnconfiguredQualificationPath,
Gatekeeper(#[from] GatekeeperError),
TrustedIdentityMismatch { did: Did, field: &'static str, expected: String, actual: String },
UntrustedAuthorityRoot { did: Did, root_did: Did },
SeatQualification { seat_id: Did, field: &'static str, reason: String },
ProofBindingMismatch { field: &'static str, expected: String, actual: String },
Ratification { field: &'static str, reason: String },
PackageBoundaryMismatch { field: &'static str, expected: String, actual: String },
ActionSignatureInvalid { disposition_id: ProtocolUuid, reason: String },
ActionBindingMismatch { field: &'static str, expected: String, actual: String },
DenominatorDrift { seat_kind: SeatKind, expected: usize, actual: usize },
MonitoringPlanMismatch { field: &'static str, expected: String, actual: String },
ThresholdDefinitionMismatch { claim_hash: ProtocolHash256, field: &'static str },
EventReceiptMismatch { event_id: ProtocolUuid, field: &'static str },
CapaAuthorizationMismatch { capa_id: ProtocolUuid, field: &'static str, expected: String, actual: String },
RecurrenceAuthorityMismatch { field: &'static str, expected: String, actual: String },
HumanClassificationInvalid { did: Did, reason: String },
StopContinuationMismatch { field: &'static str, expected: String, actual: String },
EmptyProviderDenominator,
IntegerOverflow { operation: &'static str },
InvalidEstopSet { field: &'static str, reason: String },
ResetBindingMismatch { field: &'static str, expected: String, actual: String },
ResetPrerequisite { prerequisite: &'static str },
PhaseStateMismatch { field: &'static str, expected: String, actual: String },
EnvelopeExpansion { field: &'static str, expected: String, actual: String },
InvalidPhasePromotion { current: String, requested: String, reason: String },
MandatoryNotificationMissing { destination: String },
EventCloseUnauthorized { event_id: ProtocolUuid, reason: String },
```

Tests construct and pattern-match every new variant. Receipt tests use only the
existing `ReceiptSequenceMismatch`, `ReceiptLinkMismatch`,
`ReceiptScopeMismatch`, `ReceiptReplay`, `ReceiptFork`, `ReceiptCycle`, and
`EmptyReceiptChain` variants.

## Exhaustive exact file map

No production, test, vector, or evidence path outside this table changes.
Existing Slice 2 files marked `Modify` remain owned by their existing module;
Slice 3 extends them without moving Slice 2 behavior.

| Path | Change and sole responsibility |
|---|---|
| `crates/exo-gatekeeper/Cargo.toml` | Modify: nondefault `decision-forum-test-fixtures`; no dependency change |
| `crates/decision-forum/Cargo.toml` | Modify: enable that Gatekeeper feature only in dev-dependencies; production dependency feature-free |
| `crates/exo-gatekeeper/src/lib.rs` | Modify: curated opaque trust exports and the two exact upstream domain constants |
| `crates/exo-gatekeeper/src/kernel.rs` | Modify: consume/store immutable optional root binding; ordinary kernel remains unconfigured |
| `crates/exo-gatekeeper/src/decision_forum_trust.rs` | Create: upstream manifest, capability, opaque proofs, canonical verification, test-fixture issuer |
| `crates/exo-gatekeeper/src/error.rs` | Modify: exact bootstrap/root errors |
| `crates/decision-forum/src/constitution.rs` | Modify: verifier-backed existing-domain amendment path and exact D9 mapping helpers |
| `crates/decision-forum/src/protocol/mod.rs` | Modify: declare authority and curated exports; explicitly export `ProtocolMilestoneEventInput` |
| `crates/decision-forum/src/protocol/error.rs` | Modify: exact contextual Slice 3 errors |
| `crates/decision-forum/src/protocol/domains.rs` | Modify: 42 rows above, `ALL` length 89, exhaustive `as_str` |
| `crates/decision-forum/src/protocol/trust.rs` | Modify: sole package-private action-disposition receiver; no public bypass |
| `crates/decision-forum/src/protocol/types/mod.rs` | Modify: declare/re-export exact raw Slice 3 wire and signing-payload types |
| `crates/decision-forum/src/protocol/types/review_disposition.rs` | Modify: scopes, signed targets, action kinds/targets, seven signature envelopes and payloads |
| `crates/decision-forum/src/protocol/receipt/mod.rs` | Modify: curated opaque history/stop exports |
| `crates/decision-forum/src/protocol/receipt/segment.rs` | Modify: derive ordered verified receipt facts from signed receipts |
| `crates/decision-forum/src/protocol/receipt/history.rs` | Modify: retain ordered facts and derive stop continuation |
| `crates/decision-forum/src/protocol/authority/mod.rs` | Create: child declarations and curated public exports; no behavior |
| `crates/decision-forum/src/protocol/authority/api.rs` | Create: raw evidence/result exports and compile-fail doctests; no proof constructors |
| `crates/decision-forum/src/protocol/authority/qualification.rs` | Create: root composition, seats, non-seat, package boundary/Chair, human producers |
| `crates/decision-forum/src/protocol/authority/ratification.rs` | Create: D9 byte mapping, existing amendment domain, separate receipt domain |
| `crates/decision-forum/src/protocol/authority/action.rs` | Create: exact action payload/signature orchestration through trust registry |
| `crates/decision-forum/src/protocol/authority/unanimity.rs` | Create: fixed five-seat denominators and provider/evidence floors |
| `crates/decision-forum/src/protocol/authority/intervention.rs` | Create: dissent, Chair effects, typed notification requirements |
| `crates/decision-forum/src/protocol/authority/monitoring.rs` | Create: verified monitoring catalog, exact Chair routing, event/progressive/adverse decisions |
| `crates/decision-forum/src/protocol/authority/capa.rs` | Create: signed owner actions, completion, trusted recurrence |
| `crates/decision-forum/src/protocol/authority/learning.rs` | Create: context-only learning and separate exact EventClose |
| `crates/decision-forum/src/protocol/authority/estop.rs` | Create: package-trusted votes, checked threshold, pending stop and notifications |
| `crates/decision-forum/src/protocol/authority/reset.rs` | Create: human AAR/RCA, successor/history witness, one RESET target and decision |
| `crates/decision-forum/src/protocol/authority/promotion.rs` | Create: verified envelope/ladder, exact progressive target, adjacency and no expansion |
| `crates/decision-forum/src/protocol/test_fixtures.rs` | Modify: crate-internal fixed-key fixtures only; no production constructor |
| `crates/decision-forum/src/protocol/cross_impl_tests.rs` | Modify: independent Rust actuals for all 42 Slice 3 domains |
| `crates/decision-forum/tests/support/df_protocol_001/mod.rs` | Modify: expose deterministic Slice 3 support root |
| `crates/decision-forum/tests/support/df_protocol_001/authority.rs` | Create: complete fixed-key raw-input/package/history/action/event/CAPA/reset/promotion builders |
| `crates/decision-forum/tests/df_protocol_001_slice3_api_conformance.rs` | Create: function-pointer, raw-input, error-shape, domain-inventory sentinels (89 domains) |
| `crates/decision-forum/tests/df_protocol_001_trust_bootstrap.rs` | Create: ordinary-kernel and self-consistent-attacker matrix |
| `crates/decision-forum/tests/df_protocol_001_ratification_authority.rs` | Create: domain and per-field D9 public matrix |
| `crates/decision-forum/tests/df_protocol_001_monitoring_events.rs` | Create: package Chair, thresholds, event/progressive/adverse bindings |
| `crates/decision-forum/tests/df_protocol_001_action_unanimity.rs` | Create: action replay, five-seat bodies, provider/evidence floors |
| `crates/decision-forum/tests/df_protocol_001_dissent_chair.rs` | Create: authorization versus monitoring dissent and exact Chair effects |
| `crates/decision-forum/tests/df_protocol_001_estop.rs` | Create: package trust, ceiling, evidence, pending/nine-field separation |
| `crates/decision-forum/tests/df_protocol_001_capa_learning.rs` | Create: CAPA authority, recurrence, learning and EventClose |
| `crates/decision-forum/tests/df_protocol_001_reset.rs` | Create: human producers, successor/history, full target substitution matrix |
| `crates/decision-forum/tests/df_protocol_001_promotion.rs` | Create: progressive proof, ordered ladder, every envelope field |
| `crates/decision-forum/tests/df_protocol_001_notifications.rs` | Create: exact package Chair and complete independent destination sets |
| `crates/decision-forum/tests/df_protocol_001_authority_source_guards.rs` | Create: determinism, visibility, raw-bypass and path guards |
| `tools/cross-impl-test/vectors/df_protocol_authority_v1.json` | Create: 42 complete typed canonical known-answer inputs/results |
| `tools/cross-impl-test/index.ts` | Modify: independent TypeScript Slice 3 actuals |
| `tools/cross-impl-test/index.test.ts` | Modify: 42-record and forged/missing/expected-derived tests |
| `tools/cross-impl-test/compare.sh` | Modify: require exact authority category actuals |
| `tools/cross-impl-test/compare_unit_test.sh` | Modify: reject missing/forged/expected-derived authority results |
| `.superpowers/sdd/progress.md` | Append only at gate/review closeout |
| `.superpowers/sdd/reports/df-protocol-001/03-authority/iteration-NN/*` | Create only in the evidence import commit after same-head approvals |

`Cargo.lock`, npm lockfiles, D9 predecessor, D9 Amendment 1 bytes, Slice 1
schema, and reviewed Slice 2 package schema are read-only in Slice 3.

## Full red-first implementation gates

Every gate follows this exact sequence: add the listed RED, run the exact
focused command and record the required failure, implement only its complete
GREEN contract, rerun the focused test and affected touched-crate suites, stage
only the listed paths, run `git diff --cached --check`, and commit with the exact
message. A test that passes before production behavior exists is invalid.

### Gate 00 — API, domain, visibility, and crate-boundary conformance

RED code in `df_protocol_001_slice3_api_conformance.rs`:

```rust
pub struct Slice3RawInputs {
    pub trust_manifest: DecisionForumTrustRootManifestV1,
    pub threshold: ClaimThresholdDefinitionV1,
    pub observation: ObservedClaimValueV1,
    pub action_binding: ActionBindingV1,
    pub action_vote: ProtocolActionDispositionV1,
    pub progressive_target: ProgressiveEventAuthorizationTargetV1,
    pub promotion_request: PhasePromotionRequestV1,
    pub promotion_target: PhasePromotionAuthorizationTargetV1,
    pub human_classification: HumanClassificationStatementV1,
    pub designation: HumanInvestigatorDesignationV1,
    pub aar_rca: SignedHumanAarRcaEvidenceV1,
    pub capa_owner_action: SignedCapaOwnerActionV1,
    pub recurrence: SignedRecurrenceResultV1,
    pub reset_target: ResetAuthorizationTargetV1,
    pub chair_reset: ChairResetAuthorizationV1,
    pub d9_receipt: SignedD9RatificationReceiptV1,
}

#[test]
fn every_slice3_interface_has_one_exact_compilable_owner() {
    type PackageBoundary = fn(
        &PeerReviewedProtocolPackageV1,
        &VerifiedPackageRoot,
    ) -> Result<VerifiedPackageBoundaryV1, ProtocolError>;
    let _: PackageBoundary = verify_package_boundary;

    type PackageChair = fn(
        &VerifiedPackageBoundaryV1,
        &VerifiedNonSeatAuthorityV1,
    ) -> Result<VerifiedPackageChairAuthorityV1, ProtocolError>;
    let _: PackageChair = verify_package_chair_authority;

    type Successor = fn(
        &VerifiedPackageBoundaryV1,
        &VerifiedPackageBoundaryV1,
    ) -> Result<VerifiedSuccessorPackageBoundaryV1, ProtocolError>;
    let _: Successor = verify_successor_package_boundary;

    type Monitoring = fn(
        &PeerReviewedProtocolPackageV1,
        &VerifiedPackageRoot,
        &VerifiedPackageBoundaryV1,
        &VerifiedPackageChairAuthorityV1,
        &[ClaimThresholdDefinitionV1],
    ) -> Result<VerifiedMonitoringPlanV1, ProtocolError>;
    let _: Monitoring = verify_monitoring_plan;

    type ProgressiveTarget = fn(
        &VerifiedMonitoringPlanV1,
        &VerifiedProtocolEventV1,
        &ObservedClaimValueV1,
    ) -> Result<ProgressiveEventAuthorizationTargetV1, ProtocolError>;
    let _: ProgressiveTarget = progressive_event_authorization_target;

    type Progressive = fn(
        &VerifiedMonitoringPlanV1,
        &VerifiedProtocolEventV1,
        &ProgressiveEventAuthorizationTargetV1,
        &VerifiedEligibleUnanimityDecisionV1,
        &VerifiedEligibleUnanimityDecisionV1,
    ) -> Result<VerifiedProgressiveEventDecisionV1, ProtocolError>;
    let _: Progressive = evaluate_progressive_event;

    type HumanClassify = for<'a> fn(
        &AuthorityVerifierV1<'a>,
        &VerifiedNonSeatAuthorityV1,
        &HumanClassificationStatementV1,
        ProtocolHlc,
    ) -> Result<VerifiedHumanClassificationV1, ProtocolError>;
    let _: HumanClassify = AuthorityVerifierV1::verify_human_classification;

    type ChairHuman = for<'a> fn(
        &AuthorityVerifierV1<'a>,
        VerifiedPackageChairAuthorityV1,
        &VerifiedNonSeatAuthorityV1,
        VerifiedHumanClassificationV1,
        ProtocolHlc,
    ) -> Result<VerifiedChairHumanAuthorityV1, ProtocolError>;
    let _: ChairHuman = AuthorityVerifierV1::verify_chair_human_authority;

    type Investigator = for<'a> fn(
        &AuthorityVerifierV1<'a>,
        &VerifiedEstopReferenceV1,
        &VerifiedChairHumanAuthorityV1,
        VerifiedNonSeatAuthorityV1,
        VerifiedHumanClassificationV1,
        &HumanInvestigatorDesignationV1,
        ProtocolHlc,
    ) -> Result<VerifiedHumanInvestigatorAuthorityV1, ProtocolError>;
    let _: Investigator = AuthorityVerifierV1::verify_human_investigator_authority;

    type EstopVotes = fn(
        &VerifiedPackageRoot,
        &VerifiedPackageTrustRegistryV1,
        &VerifiedProtocolEventV1,
        &VerifiedActiveRosterSnapshotV1,
        &[ProtocolActionDispositionV1],
        ProtocolHlc,
    ) -> Result<VerifiedEstopActionDispositionSetV1, ProtocolError>;
    let _: EstopVotes = verify_estop_action_dispositions;

    type ResetTarget = fn(
        ProtocolUuid,
        &VerifiedEstopReferenceV1,
        &VerifiedStopContinuationV1,
        &VerifiedSuccessorPackageBoundaryV1,
        &VerifiedHumanInvestigatorAuthorityV1,
        &VerifiedHumanAarRcaV1,
        &VerifiedCapaCompletionV1,
        &VerifiedRecurrenceResultV1,
        ProtocolHash256,
        ProtocolHash256,
        &VerifiedChairHumanAuthorityV1,
    ) -> Result<ResetAuthorizationTargetV1, ProtocolError>;
    let _: ResetTarget = reset_authorization_target;

    type EvaluateReset = fn(
        &ResetAuthorizationTargetV1,
        &VerifiedEstopReferenceV1,
        &VerifiedStopContinuationV1,
        &VerifiedSuccessorPackageBoundaryV1,
        &VerifiedHumanInvestigatorAuthorityV1,
        &VerifiedHumanAarRcaV1,
        &VerifiedCapaCompletionV1,
        &VerifiedRecurrenceResultV1,
        &VerifiedEligibleUnanimityDecisionV1,
        &VerifiedEligibleUnanimityDecisionV1,
        &VerifiedChairResetAuthorizationV1,
        ProtocolHlc,
    ) -> Result<VerifiedResetDecisionV1, ProtocolError>;
    let _: EvaluateReset = evaluate_reset;

    let Slice3RawInputs {
        trust_manifest: _, threshold: _, observation: _, action_binding: _,
        action_vote: _, progressive_target: _, promotion_request: _,
        promotion_target: _, human_classification: _, designation: _, aar_rca: _,
        capa_owner_action: _, recurrence: _, reset_target: _, chair_reset: _,
        d9_receipt: _,
    } = support::df_protocol_001::authority::all_raw_inputs();
    assert_eq!(ProtocolHashDomain::ALL.len(), 89);
}

#[test]
fn slice3_error_shapes_compile_exactly() {
    let did = support::did("did:exo:error");
    let hash = ProtocolHash256::ZERO;
    let _ = ProtocolError::PackageBoundaryMismatch {
        field: "constitution_hash", expected: hash.to_string(), actual: hash.to_string(),
    };
    let _ = ProtocolError::HumanClassificationInvalid { did, reason: "invalid root".into() };
    let _ = ProtocolError::StopContinuationMismatch {
        field: "chain_root", expected: hash.to_string(), actual: hash.to_string(),
    };
    let _ = ProtocolError::ResetBindingMismatch {
        field: "human_aar_rca_hash", expected: hash.to_string(), actual: hash.to_string(),
    };
    let _ = ProtocolError::ResetPrerequisite { prerequisite: "recurrence_passed" };
    let _ = ProtocolError::EmptyProviderDenominator;
    let _ = ProtocolError::IntegerOverflow { operation: "2 * active providers" };
}

#[test]
fn remaining_public_api_function_items_match_exact_signatures() {
    let _: fn(
        &VerifiedPackageRoot, &VerifiedExecutionHistory, &VerifiedMonitoringPlanV1,
        &ProtocolEvent, &VerifiedExecutionReceiptReferenceV1,
    ) -> Result<VerifiedProtocolEventV1, ProtocolError> = verify_protocol_event;
    let _: fn(
        &VerifiedMonitoringPlanV1, &VerifiedProtocolEventV1,
        &VerifiedEligibleUnanimityDecisionV1, &VerifiedEligibleUnanimityDecisionV1,
        ProtocolHlc,
    ) -> Result<(VerifiedAdverseEventDecisionV1, PendingNotificationRequirementV1), ProtocolError>
        = evaluate_adverse_event;
    let _: fn(
        &VerifiedMonitoringPlanV1, &VerifiedProtocolEventV1,
        &VerifiedEligibleUnanimityDecisionV1, &VerifiedEligibleUnanimityDecisionV1,
        ProtocolHlc,
    ) -> Result<(VerifiedAdverseEventDecisionV1, PendingNotificationRequirementV1), ProtocolError>
        = evaluate_ai_sdlc_transgression;
    let _: for<'a> fn(
        &AuthorityVerifierV1<'a>, &VerifiedPackageRoot, &VerifiedPackageTrustRegistryV1,
        &ActionBindingV1, &[ProtocolActionDispositionV1], ProtocolHlc,
    ) -> Result<VerifiedEligibleUnanimityDecisionV1, ProtocolError>
        = AuthorityVerifierV1::evaluate_eligible_unanimity;
    let _: fn(
        &VerifiedPackageRoot, &VerifiedPackageTrustRegistryV1,
        &VerifiedMonitoringPlanV1, &ProtocolActionDispositionV1,
        DissentContext, ProtocolHlc,
    ) -> Result<(VerifiedDissentDecisionV1, PendingNotificationRequirementV1), ProtocolError>
        = derive_dissent_decision;
    let _: fn(
        &PeerReviewedProtocolPackageV1, &VerifiedPackageRoot,
    ) -> Result<VerifiedEnvelopePhaseLadderV1, ProtocolError>
        = verify_envelope_phase_ladder;
    let _: fn(
        ProtocolUuid, &VerifiedEnvelopePhaseLadderV1, &VerifiedProtocolPhaseStateV1,
        &VerifiedProgressiveEventDecisionV1, &PhasePromotionRequestV1,
    ) -> Result<PhasePromotionAuthorizationTargetV1, ProtocolError>
        = phase_promotion_authorization_target;
    let _: fn(
        &VerifiedEnvelopePhaseLadderV1, &VerifiedProtocolPhaseStateV1,
        &VerifiedProgressiveEventDecisionV1, &PhasePromotionRequestV1,
        &PhasePromotionAuthorizationTargetV1, &VerifiedEligibleUnanimityDecisionV1,
        &VerifiedEligibleUnanimityDecisionV1, ProtocolHlc,
    ) -> Result<(PendingPhasePromotionDecisionV1, PendingNotificationRequirementV1), ProtocolError>
        = evaluate_phase_promotion;
    let _: fn(
        &VerifiedPackageRoot, &VerifiedNonSeatAuthorityV1, &SignedCapaOwnerActionV1,
    ) -> Result<VerifiedCapaOwnerActionV1, ProtocolError> = verify_capa_owner_action;
    let _: fn(
        &VerifiedProtocolEventV1, &VerifiedCapaOwnerActionV1,
    ) -> Result<PendingCapaOpenDecisionV1, ProtocolError> = open_capa_for_event;
    let _: fn(
        &VerifiedProtocolEventV1, &PendingCapaOpenDecisionV1,
        &VerifiedCapaOwnerActionV1, &CapaRecord, &VerifiedExecutionReceiptReferenceV1,
    ) -> Result<VerifiedCapaCompletionV1, ProtocolError> = verify_capa_completion;
    let _: fn(
        &VerifiedNonSeatAuthorityV1,
    ) -> Result<VerifiedRecurrenceAuthorityV1, ProtocolError> = verify_recurrence_authority;
    let _: fn(
        &VerifiedRecurrenceAuthorityV1, &VerifiedEstopReferenceV1,
        &VerifiedCapaCompletionV1, &SignedRecurrenceResultV1,
        &VerifiedExecutionReceiptReferenceV1,
    ) -> Result<VerifiedRecurrenceResultV1, ProtocolError> = verify_recurrence_result;
    let _: fn(
        &VerifiedProtocolEventV1, Option<&VerifiedCapaCompletionV1>,
        Option<&VerifiedRecurrenceResultV1>, &SystemicLearningRecord, ProtocolHlc,
    ) -> Result<PendingSystemicLearningDecisionV1, ProtocolError> = prepare_systemic_learning;
    let _: fn(
        &VerifiedProtocolEventV1, &PendingSystemicLearningDecisionV1,
        &VerifiedEligibleUnanimityDecisionV1, &VerifiedEligibleUnanimityDecisionV1,
        ProtocolHlc,
    ) -> Result<VerifiedEventCloseDecisionV1, ProtocolError> = authorize_event_close;
    let _: fn(
        &VerifiedPackageRoot, &VerifiedPackageTrustRegistryV1, ProtocolHlc,
    ) -> Result<VerifiedActiveRosterSnapshotV1, ProtocolError> = verify_active_roster_snapshot;
    let _: fn(
        &PeerReviewedProtocolPackageV1, &VerifiedPackageRoot,
    ) -> Result<VerifiedEvidenceFloorV1, ProtocolError> = verify_evidence_floor;
    let _: fn(
        &VerifiedProtocolEventV1, &VerifiedActiveRosterSnapshotV1,
        &VerifiedEstopActionDispositionSetV1, ProtocolHlc,
    ) -> Result<VerifiedEstopProviderApprovalSetV1, ProtocolError>
        = verify_estop_provider_approvals;
    let _: fn(
        ProtocolUuid, &VerifiedMonitoringPlanV1, &VerifiedProtocolEventV1,
        &VerifiedActiveRosterSnapshotV1, &VerifiedEvidenceFloorV1,
        &VerifiedEstopProviderApprovalSetV1, ProtocolHlc,
    ) -> Result<(PendingEstopDecisionV1, PendingNotificationRequirementV1), ProtocolError>
        = evaluate_estop_threshold;
    let _: fn(
        &PendingEstopDecisionV1, &EstopAuthorization,
        &VerifiedExecutionReceiptReferenceV1,
    ) -> Result<VerifiedEstopReferenceV1, ProtocolError> = verify_estop_reference;
    let _: fn(
        &VerifiedEstopReferenceV1, &VerifiedHumanInvestigatorAuthorityV1,
        &SignedHumanAarRcaEvidenceV1,
    ) -> Result<VerifiedHumanAarRcaV1, ProtocolError> = verify_human_aar_rca;
    let _: fn(
        &ResetAuthorizationTargetV1, &VerifiedChairHumanAuthorityV1,
        &ChairResetAuthorizationV1,
    ) -> Result<VerifiedChairResetAuthorizationV1, ProtocolError>
        = verify_chair_reset_authorization;
    let _: for<'a> fn(
        &AuthorityVerifierV1<'a>, &[u8], &[u8], &ConstitutionCorpus,
        &ConstitutionCorpus, &ConstitutionQuorum, &BTreeSet<Did>,
        &[(Did, Signature)], &SignedD9RatificationReceiptV1,
    ) -> Result<VerifiedD9Amendment1RatificationV1, ProtocolError>
        = verify_d9_amendment_1_ratification;
}
```

The same test destructures `Slice3RawInputs`, whose complete literal builder
constructs every raw public Slice 3 record, signing payload, enum variant, and
signature envelope. The crate-internal unit sentinel is exact because integration
code must not access either method:

```rust
#[test]
fn package_private_method_items_match_exact_signatures() {
    type StopContinuation = fn(
        &VerifiedExecutionHistory,
        &VerifiedEstopReferenceV1,
        &VerifiedPackageBoundaryV1,
        &VerifiedSuccessorPackageBoundaryV1,
    ) -> Result<VerifiedStopContinuationV1, ProtocolError>;
    let _: StopContinuation = VerifiedExecutionHistory::verify_stop_continuation;

    type ActionDisposition = fn(
        &VerifiedPackageTrustRegistryV1,
        &VerifiedPackageRoot,
        &ProtocolActionDispositionV1,
    ) -> Result<VerifiedActionDispositionV1, ProtocolError>;
    let _: ActionDisposition =
        VerifiedPackageTrustRegistryV1::verify_protocol_action_disposition;
}
```

Add these doctests to `authority/api.rs` and `trust.rs`:

```rust,compile_fail
use exochain_decision_forum::protocol::VerifiedStopContinuationV1;
fn leak(value: &VerifiedStopContinuationV1) { let _ = value.continuation_hash; }
```

```rust,compile_fail
use exochain_decision_forum::protocol::{VerifiedPackageRoot, VerifiedPackageTrustRegistryV1};
fn bypass(registry: &VerifiedPackageTrustRegistryV1, root: &VerifiedPackageRoot) {
    let _ = registry.verify_protocol_action_disposition(root, unreachable!());
}
```

```rust,compile_fail
use exochain_decision_forum::protocol::*;
type MissingRegistry = fn(
    &VerifiedPackageRoot,
    &VerifiedProtocolEventV1,
    &VerifiedActiveRosterSnapshotV1,
    &[ProtocolActionDispositionV1],
    ProtocolHlc,
) -> Result<VerifiedEstopActionDispositionSetV1, ProtocolError>;
let _: MissingRegistry = verify_estop_action_dispositions;
```

Commands:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_slice3_api_conformance every_slice3_interface_has_one_exact_compilable_owner -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_slice3_api_conformance slice3_error_shapes_compile_exactly -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_slice3_api_conformance remaining_public_api_function_items_match_exact_signatures -- --exact --nocapture
cargo test -p exochain-decision-forum --lib protocol::authority::api::tests::package_private_method_items_match_exact_signatures -- --exact --nocapture
cargo test -p exochain-decision-forum --doc
cargo check -p exochain-gatekeeper -p exochain-decision-forum --all-targets
```

Expected RED: unresolved exact imports/function items or missing `ALL` rows; the
doctest gate fails if private/package-private boundaries are public or the
E-STOP registry becomes optional. Minimum GREEN: every pointer, literal raw
input, error shape, 89-domain inventory, compile-fail case, and both crates
compile. Affected suites: both touched crates plus doctests. Stage Gatekeeper
trust owners, protocol module/error/domain/type/module skeletons, support root,
and API conformance test. Commit:
`test(decision-forum): freeze slice 3 authority API`.

### Gate 01 — immutable operator bootstrap and exact qualification layers

RED code:

```rust
#[test]
fn self_consistent_attacker_cannot_bootstrap_binding_trust() {
    let attack = fixture().self_consistent_attacker_bootstrap();
    let kernel = Kernel::new(attack.corpus(), InvariantSet::all());
    assert_eq!(
        attack.qualify_all_layers(&kernel).expect_err("ordinary kernel refuses roots"),
        ProtocolError::UnconfiguredQualificationPath,
    );

    let legitimate = fixture().configured_kernel();
    assert!(matches!(
        attack.replace_manifest_and_qualify(&legitimate)
            .expect_err("attacker digest and key are not operator capability"),
        ProtocolError::Gatekeeper(GatekeeperError::DecisionForumBootstrapMismatch { .. })
            | ProtocolError::Gatekeeper(
                GatekeeperError::DecisionForumRootBindingMismatch { .. }
            )
    ));
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_trust_bootstrap self_consistent_attacker_cannot_bootstrap_binding_trust -- --exact --nocapture
```

Expected RED: qualification succeeds or the exact fail-closed error/API is
absent. Minimum GREEN: consumed capability, canonical manifest/domain, ordinary
kernel refusal, narrow root verification, identity/controller/authority/seat
layers, no key-map access, and wrong root class/tenant/corpus/time/key ID/
payload/signature negatives. Affected suites: Gatekeeper and Decision Forum all
targets. Stage only both Cargo manifests and Gatekeeper trust/kernel/error/lib
owners plus this test. Commit:
`feat(gatekeeper): add immutable Decision Forum trust verification`.

### Gate 02 — exact D9 domains, bytes, mapping, and per-field errors

RED code:

```rust
#[test]
fn d9_public_mutations_report_the_exact_owning_field() {
    let fx = fixture().d9_ratification();
    assert!(fx.verify().is_ok());
    for &(mutation, expected_field) in D9_PUBLIC_EXPECTED_FIELDS {
        let error = fx.verify_public_mutation(mutation)
            .expect_err("every mutation must fail closed");
        assert!(matches!(
            error,
            ProtocolError::Ratification { field, .. } if field == expected_field
        ));
    }
}

#[test]
fn d9_internal_article_mapping_reports_article_mapping() {
    let fx = fixture().d9_ratification();
    for &(mutation, expected_field) in D9_MAPPING_EXPECTED_FIELDS {
        let error = fx.verify_mapped_article_mutation(mutation)
            .expect_err("derived Article mutation must fail");
        assert!(matches!(
            error,
            ProtocolError::Ratification { field, .. } if field == expected_field
        ));
    }
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_ratification_authority d9_public_mutations_report_the_exact_owning_field -- --exact --nocapture
cargo test -p exochain-decision-forum --lib protocol::authority::ratification::tests::d9_internal_article_mapping_reports_article_mapping -- --exact --nocapture
```

Expected RED: missing verifier/domain or any observed error field differs from
the frozen tables. Minimum GREEN: exact predecessor/amendment BLAKE3, derived
Article, existing amendment-domain signatures, separately signed row-3 receipt,
exact predecessor/result corpus/version/count/quorum/signer/timestamp equality,
and cross-domain rejection. Affected suite: Decision Forum all targets plus D9
unit tests. Stage constitution, domains, ratification, exact errors, and D9 test.
Commit: `feat(decision-forum): verify exact D9 ratification`.

### Gate 03 — package boundary, exact Chair, monitoring, and progressive target

RED code:

```rust
#[test]
fn monitoring_and_progressive_authority_reject_every_rebinding() {
    let fx = fixture().monitoring();
    let verified = fx.verify().expect("exact package monitoring");
    for mutation in [
        PlanMutation::WrongPackage,
        PlanMutation::AddedThreshold,
        PlanMutation::OmittedThreshold,
        PlanMutation::ChangedComparator,
        PlanMutation::ChangedValue,
        PlanMutation::ClaimCollision,
        PlanMutation::NonChairEscalationDid,
        PlanMutation::WrongChairAuthority,
        PlanMutation::ChangedEventDomain,
        PlanMutation::CrossRootReplay,
    ] {
        assert!(matches!(
            fx.verify_mutation(mutation),
            Err(ProtocolError::PackageBoundaryMismatch { .. })
                | Err(ProtocolError::MonitoringPlanMismatch { .. })
                | Err(ProtocolError::ThresholdDefinitionMismatch { .. })
                | Err(ProtocolError::ProofBindingMismatch { .. })
        ));
    }

    for mutation in [
        ProgressiveMutation::SameIdDifferentEvent,
        ProgressiveMutation::SameObservationDifferentThreshold,
        ProgressiveMutation::ChangedMonitoringRoot,
        ProgressiveMutation::ChangedObservedEvidence,
        ProgressiveMutation::OtherPackageTarget,
    ] {
        assert!(matches!(
            fx.evaluate_progressive_mutation(&verified, mutation),
            Err(ProtocolError::ActionBindingMismatch { .. })
                | Err(ProtocolError::ThresholdDefinitionMismatch { .. })
                | Err(ProtocolError::MonitoringPlanMismatch { .. })
        ));
    }
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_monitoring_events monitoring_and_progressive_authority_reject_every_rebinding -- --exact --nocapture
```

Expected RED: raw plan/DID/threshold or same-ID changed event reaches a decision.
Minimum GREEN: opaque boundary and package Chair, exact escalation equality,
one-to-one catalog, integer comparison, row-13 threshold result, row-14 target,
and dual-body exact target matching. Affected suite: Decision Forum all targets.
Stage qualification/monitoring/action/domain/support/event test paths. Commit:
`feat(decision-forum): bind monitoring authority to package`.

### Gate 04 — package-trusted E-STOP before provider counting

RED code:

```rust
#[test]
fn estop_counts_only_votes_verified_by_the_supplied_exact_registry() {
    let fx = fixture().estop();
    assert_eq!(fx.valid_approval_count(), 3);
    for mutation in [
        EstopVoteMutation::SelfSigned,
        EstopVoteMutation::OtherTenantRegistry,
        EstopVoteMutation::OtherPackageRegistry,
        EstopVoteMutation::OtherRootRegistry,
        EstopVoteMutation::StaleAttestation,
        EstopVoteMutation::WrongContext,
        EstopVoteMutation::WrongBody,
        EstopVoteMutation::WrongEvent,
        EstopVoteMutation::WrongScope,
    ] {
        let error = fx.verify_vote_mutation(mutation)
            .expect_err("untrusted vote must not reach aggregation");
        assert!(matches!(
            error,
            ProtocolError::ActionSignatureInvalid { .. }
                | ProtocolError::ActionBindingMismatch { .. }
                | ProtocolError::InvalidEstopSet { .. }
                | ProtocolError::ProofBindingMismatch { .. }
        ));
        assert_eq!(fx.count_after_failed_mutation(), 0);
    }
}

#[test]
fn estop_math_and_materialization_boundary_are_exact() {
    for (active, expected) in [(1, 1), (2, 2), (3, 2), (4, 3)] {
        assert_eq!(checked_two_thirds_ceiling(active).expect("valid"), expected);
    }
    assert_eq!(checked_two_thirds_ceiling(0), Err(ProtocolError::EmptyProviderDenominator));
    let materialized = serde_json::to_value(fixture().estop().materialized_record())
        .expect("materialized E-STOP transport");
    let materialized_fields = materialized.as_object().expect("object").keys()
        .map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(materialized_fields, BTreeSet::from([
        "estop_id", "scope_hash", "active_provider_classes",
        "approve_provider_classes", "required_provider_class_count",
        "independent_evidence_classes", "threshold_result", "fired_at",
        "receipt_root",
    ]));
    let pending = serde_json::to_value(fixture().estop().pending_decision())
        .expect("pending E-STOP transport");
    assert!(!pending.as_object().expect("object").contains_key("receipt_root"));
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_estop estop_counts_only_votes_verified_by_the_supplied_exact_registry -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_estop estop_math_and_materialization_boundary_are_exact -- --exact --nocapture
cargo test -p exochain-decision-forum --doc
```

Expected RED: wrong-registry/raw votes are counted, exact arithmetic is absent,
or pending/materialized shapes drift. Missing registry is closed only by Gate 00
compile-fail. Minimum GREEN: package-private verification before aggregation,
rows 19-24 hashes, fixed four-provider policy, two evidence classes, exact
checked table, exact nine fields, no pending receipt, complete typed E-STOP
notification. Affected suite: Decision Forum all targets and doctests. Stage
trust/action/estop/domain/support/E-STOP test. Commit:
`feat(decision-forum): enforce package-trusted E-STOP`.

### Gate 05 — CAPA owner authority, recurrence, learning, and EventClose

RED code:

```rust
#[test]
fn capa_recurrence_and_close_have_distinct_exact_authorities() {
    let fx = fixture().capa();
    assert!(fx.authorized_completion().is_ok());
    for mutation in [
        CapaMutation::OwnerImpersonation,
        CapaMutation::UnsignedOpen,
        CapaMutation::UnsignedCompletion,
        CapaMutation::ReceiptWithoutOwnerSignature,
        CapaMutation::WrongEvent,
        CapaMutation::WrongStop,
        CapaMutation::WrongCapa,
        CapaMutation::WrongRoot,
        CapaMutation::SelfSignedRecurrence,
        CapaMutation::WrongRecurrenceScope,
        CapaMutation::FailedRecurrence,
    ] {
        assert!(fx.verify_mutation(mutation).is_err());
    }

    let learning = fx.prepare_learning().expect("context-only learning");
    assert!(!learning.grants_event_close());
    assert!(matches!(
        fx.close_without_event_close_votes(&learning),
        Err(ProtocolError::EventCloseUnauthorized { .. })
    ));
    assert!(fx.close_with_exact_event_close_target(&learning).is_ok());
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_capa_learning capa_recurrence_and_close_have_distinct_exact_authorities -- --exact --nocapture
```

Expected RED: raw owner/CAPA/recurrence/learning satisfies completion or close.
Minimum GREEN: row-25 owner signatures for open/complete, exact record and
receipt, independently rooted row-28 passed recurrence, row-30 context-only
learning, separate row-31 EventClose target, and row-32 dual-body decision.
Affected suite: Decision Forum all targets. Stage CAPA/learning/action/domain/
support/test paths. Commit:
`feat(decision-forum): authorize CAPA and event close`.

### Gate 06 — exact human producers, successor witness, and one RESET target

RED code:

```rust
#[test]
fn reset_rejects_every_post_signature_prerequisite_substitution() {
    let fx = fixture().reset();
    assert!(fx.verify().is_ok());
    for mutation in [
        ResetMutation::AiDidLabeledHuman,
        ResetMutation::SelfSignedHumanClassification,
        ResetMutation::ExpiredHumanClassification,
        ResetMutation::NonPackageChair,
        ResetMutation::UndesignatedHuman,
        ResetMutation::DifferentAar,
        ResetMutation::DifferentRca,
        ResetMutation::DifferentCapaCompletion,
        ResetMutation::DifferentRecurrenceResult,
        ResetMutation::DifferentStopContinuation,
        ResetMutation::SuccessorStalePriorChain,
        ResetMutation::SuccessorChangedConstitution,
        ResetMutation::SuccessorDifferentPredecessor,
        ResetMutation::StopOnlyInUnrelatedHistory,
        ResetMutation::DifferentCouncilEligibleSet,
        ResetMutation::DifferentAiIrbEligibleSet,
        ResetMutation::DifferentChairKey,
    ] {
        assert!(matches!(
            fx.verify_after_signatures(mutation),
            Err(ProtocolError::HumanClassificationInvalid { .. })
                | Err(ProtocolError::PackageBoundaryMismatch { .. })
                | Err(ProtocolError::StopContinuationMismatch { .. })
                | Err(ProtocolError::ResetBindingMismatch { .. })
                | Err(ProtocolError::ResetPrerequisite { .. })
        ));
    }
}

#[test]
fn stop_continuation_is_derived_from_package_and_ordered_receipt_facts() {
    let fx = fixture().reset();
    let continuation = fx.verify_stop_continuation().expect("exact history");
    assert_eq!(continuation, fx.reverify_stop_continuation().expect("deterministic"));
    for mutation in [
        StopHistoryMutation::OmitStopReceipt,
        StopHistoryMutation::BreakPreviousReceiptLink,
        StopHistoryMutation::BreakSequence,
        StopHistoryMutation::ForkAfterStop,
        StopHistoryMutation::CrossTenantHistory,
        StopHistoryMutation::ValidRootWithStalePriorChain,
    ] {
        assert!(fx.verify_stop_history_mutation(mutation).is_err());
    }
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_reset reset_rejects_every_post_signature_prerequisite_substitution -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_reset stop_continuation_is_derived_from_package_and_ordered_receipt_facts -- --exact --nocapture
```

Expected RED: no exact opaque producer, generic successor/history, or a
substituted prerequisite still satisfies previously signed votes. Minimum GREEN:
the three exact `AuthorityVerifierV1` producers, exact AAR/RCA, ordered receipt
facts, package/successor boundaries, row-41 continuation, row-40 target shared by
both bodies and Chair, and row-42 decision. Affected suites: both touched crates,
Decision Forum receipt-chain tests, and all Decision Forum targets. Stage
qualification/receipt/reset/action/domain/support/reset test. Commit:
`feat(decision-forum): require complete RESET authority`.

### Gate 07 — exact progressive-decision promotion and no envelope expansion

RED code:

```rust
#[test]
fn promotion_signatures_bind_the_exact_progressive_decision() {
    let fx = fixture().promotion();
    assert!(fx.promote_next_phase().is_ok());
    for mutation in [
        PromotionMutation::SameEventIdDifferentEvent,
        PromotionMutation::SamePhaseDifferentProgressiveProof,
        PromotionMutation::DifferentThresholdDecision,
        PromotionMutation::CrossMonitoringRootReplay,
        PromotionMutation::SamePhase,
        PromotionMutation::SkippedPhase,
        PromotionMutation::ReorderedLadder,
        PromotionMutation::UnknownPhase,
        PromotionMutation::ChangedPermittedActions,
        PromotionMutation::ChangedSystems,
        PromotionMutation::ChangedTenants,
        PromotionMutation::ChangedDatasets,
        PromotionMutation::ChangedActorClasses,
        PromotionMutation::IncreasedAnyResourceCeiling,
        PromotionMutation::IncreasedRiskCeiling,
        PromotionMutation::ChangedStart,
        PromotionMutation::ExtendedEnd,
    ] {
        assert!(matches!(
            fx.promote_mutation(mutation),
            Err(ProtocolError::ActionBindingMismatch { .. })
                | Err(ProtocolError::InvalidPhasePromotion { .. })
                | Err(ProtocolError::EnvelopeExpansion { .. })
                | Err(ProtocolError::PhaseStateMismatch { .. })
        ));
    }
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_promotion promotion_signatures_bind_the_exact_progressive_decision -- --exact --nocapture
```

Expected RED: same-ID event or another progressive decision replays into signed
promotion, or any phase/envelope mutation passes. Minimum GREEN: exact row-15
progressive decision, row-17 target in both body bindings, ordered immediate
adjacency, every envelope field equal, row-18 pending decision, and exact Chair
notice. Affected suite: Decision Forum all targets. Stage promotion/monitoring/
action/domain/support/test paths. Commit:
`feat(decision-forum): constrain phase promotion`.

### Gate 08 — exact package Chair and complete independent notifications

RED code:

```rust
#[test]
fn notifications_use_the_package_chair_and_preserve_every_destination() {
    let fx = fixture().notifications();
    assert!(matches!(
        fx.package_with_non_chair_escalation_destination(),
        Err(ProtocolError::MonitoringPlanMismatch {
            field: "escalation_destination", ..
        })
    ));

    for cause in [
        NotificationCauseV1::AuthorizationDissent,
        NotificationCauseV1::MonitoringDissent,
        NotificationCauseV1::AdverseEvent,
        NotificationCauseV1::AiSdlcTransgression,
        NotificationCauseV1::Estop,
        NotificationCauseV1::PhasePromotion,
    ] {
        let requirement = fx.requirement(cause).expect("typed requirement");
        assert_eq!(requirement.required_destinations(), fx.expected_destinations(cause));
        let partial = fx.one_success_one_failure(&requirement);
        assert!(matches!(
            requirement.validate_destination_coverage(&partial),
            Err(ProtocolError::MandatoryNotificationMissing { .. })
        ));
        assert_eq!(requirement.required_destinations(), fx.expected_destinations(cause));
    }
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_notifications notifications_use_the_package_chair_and_preserve_every_destination -- --exact --nocapture
```

Expected RED: arbitrary escalation DID becomes typed Chair or one delivery
suppresses another. Minimum GREEN: package-derived Chair authority in monitoring,
complete typed sets, row-12 immutable requirement hash, and no delivery-attempt
mutation. Affected suite: Decision Forum all targets. Stage qualification/
monitoring/intervention/notification/support/test paths. Commit:
`feat(decision-forum): derive mandatory notification requirements`.

### Gate 09 — fixed unanimity, replay, dissent, and Chair effects

Complete RED code in the two exact integration targets:

```rust
#[test]
fn action_unanimity_rejects_replay_and_denominator_shrinkage() {
    let fx = fixture().actions();
    assert!(fx.exact_council_unanimity().is_ok());
    assert!(fx.exact_ai_irb_unanimity().is_ok());
    for mutation in [
        ActionMutation::Tenant,
        ActionMutation::Protocol,
        ActionMutation::Version,
        ActionMutation::PackageRoot,
        ActionMutation::ActionKind,
        ActionMutation::Scope,
        ActionMutation::Target,
        ActionMutation::ReviewBundle,
        ActionMutation::EligibleSet,
        ActionMutation::EvidenceGraph,
        ActionMutation::DispositionId,
        ActionMutation::SeatId,
        ActionMutation::SeatKind,
        ActionMutation::ProviderClass,
        ActionMutation::Choice,
        ActionMutation::SeatAttestation,
        ActionMutation::ContextManifest,
        ActionMutation::SignedAt,
        ActionMutation::Signature,
    ] {
        assert!(fx.evaluate_mutation(mutation).is_err());
    }
    for mutation in [
        BodyMutation::MissingSeat,
        BodyMutation::RecusedSeatRemoved,
        BodyMutation::ExpiredSeatRemoved,
        BodyMutation::ConflictedSeatRemoved,
        BodyMutation::Abstention,
        BodyMutation::Rejection,
        BodyMutation::ProviderFloorMissing,
        BodyMutation::IndependentEvidenceFloorMissing,
    ] {
        assert!(matches!(
            fx.evaluate_body_mutation(mutation),
            Err(ProtocolError::DenominatorDrift { .. })
                | Err(ProtocolError::SeatQualification { .. })
                | Err(ProtocolError::ActionBindingMismatch { .. })
                | Err(ProtocolError::ProofBindingMismatch { .. })
        ));
    }
}
```

```rust
#[test]
fn dissent_and_chair_have_exact_non_curing_effects() {
    let fx = fixture().dissent_and_chair();
    let (authorization, authorization_notice) = fx.authorization_dissent()
        .expect("authorization dissent");
    assert_eq!(authorization.effect(), DissentEffect::AuthorizationBlocked);
    assert!(authorization_notice.required_destinations().contains(
        &NotificationDestinationV1::Chair(fx.package_chair().clone())
    ));

    let (monitoring, monitoring_notice) = fx.monitoring_dissent()
        .expect("monitoring dissent");
    assert_eq!(monitoring.effect(), DissentEffect::ChairAlertAndContinuingReview);
    assert!(!monitoring.grants_protocol_wide_stop());
    assert!(monitoring_notice.required_destinations().contains(
        &NotificationDestinationV1::ContinuingReview {
            protocol_id: fx.protocol_id().to_owned(),
        }
    ));

    assert!(!fx.chair_approve_with_missing_ai_vote().expect("endorsement").is_binding());
    assert_eq!(
        fx.chair_reject().expect("hold").effect(),
        ChairEffect::ScopedHumanOverrideHold,
    );
}
```

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_action_unanimity action_unanimity_rejects_replay_and_denominator_shrinkage -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_dissent_chair dissent_and_chair_have_exact_non_curing_effects -- --exact --nocapture
```

Expected RED: a replay dimension passes, a body drops below five without typed
failure, authorization dissent does not block, monitoring dissent manufactures
a stop, or Chair approval cures a body. Minimum GREEN: exact row-8/9 action
signature path, fixed five/five decisions with provider/evidence precedence,
row-10 proof, row-11 dissent, exact package Chair notice, endorsement-only
approve, and exact scoped hold on reject. Affected suite: Decision Forum all
targets. Stage action/unanimity/intervention/domain/support and both tests.
Commit: `feat(decision-forum): enforce fixed action unanimity`.

### Gate 10 — deterministic source guards and 42-domain parity

RED code:

```rust
#[test]
fn authority_surface_has_no_raw_or_nondeterministic_bypass() {
    let source = authority_sources();
    for forbidden in [
        "HashMap", "HashSet", "f32", "f64", "SystemTime", "Instant::now",
        "Uuid::new_v4", "thread_rng", "rand::", "unsafe {",
        "pub fn new_verified", "pub fn unchecked",
        "receipt_root != ProtocolHash256::ZERO",
        "pub fn verify_protocol_action_disposition",
    ] {
        assert!(!source.contains(forbidden), "forbidden source: {forbidden}");
    }
    assert_eq!(ProtocolHashDomain::ALL.len(), 89);
    // Slice 2 frozen inventory is the first 47 variants; Slice 3 appends 42.
    assert_eq!(
        slice3_domain_vector_names(),
        ProtocolHashDomain::ALL[47..]
            .iter()
            .map(|domain| domain.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(ProtocolHashDomain::ALL[47..].len(), 42);
}

/// Exact ordered domain strings for the 42 Slice 3 registry rows (must match
/// `ProtocolHashDomain::ALL[47..].as_str()` and the cross-impl vector names).
fn slice3_domain_vector_names() -> Vec<&'static str> {
    ProtocolHashDomain::ALL[47..]
        .iter()
        .map(|domain| domain.as_str())
        .collect()
}
```

Exact commands, including the command missing from Wave 3 Gate 10:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_authority_source_guards authority_surface_has_no_raw_or_nondeterministic_bypass -- --exact --nocapture
cargo test -p exochain-decision-forum --lib protocol::cross_impl_tests::slice3_authority_known_answers -- --exact --nocapture
npm --prefix tools/cross-impl-test test -- --test-name-pattern='slice 3 authority known answers'
./tools/cross-impl-test/compare_unit_test.sh
./tools/cross-impl-test/compare.sh --verbose
```

Expected RED: forbidden source, incomplete 42-domain inventory, missing actual,
canonical CBOR/hash/signature mismatch, or forged/expected-derived output is
accepted. Minimum GREEN: independent integer-only Rust/TypeScript actuals for
all 42 registry rows and behavioral vectors for action binding, fixed unanimity,
checked ceiling, monitoring comparison, notification route, CAPA, stop
continuation, RESET, and promotion. Affected suites: Decision Forum all targets,
both parity runners, policy tests. Stage source guard, domains, vectors,
cross-implementation Rust/TypeScript/runners. Commits:

1. `test(decision-forum): guard protocol authority boundaries`
2. `test(cross-impl): compare protocol authority decisions`

### Gate 11 — immutable same-head external review evidence

Freeze `IMPLEMENTATION_HEAD` only after Gates 00-10 and every full gate below.
Fresh read-only specification and technical reviewers inspect the same
`SLICE_BASE..IMPLEMENTATION_HEAD`. After both approve that head, a fresh
whole-slice reviewer inspects the same range. The sole later repository write is
an evidence-only direct child that imports the three immutable reports and
sidecars plus a non-recursive manifest and progress append. Commit:
`docs(decision-forum): record protocol authority evidence`.

## Focused, full, policy, and bypass gates

Run this complete set from a clean worktree before every external review:

```bash
cargo check -p exochain-gatekeeper -p exochain-decision-forum --all-targets
cargo test -p exochain-gatekeeper --all-targets
cargo test -p exochain-decision-forum --all-targets
cargo test -p exochain-decision-forum --doc
cargo clippy -p exochain-gatekeeper -p exochain-decision-forum --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
./tools/cross-impl-test/compare_unit_test.sh
./tools/cross-impl-test/compare.sh --verbose
python3 tools/license_headers.py --check
bash tools/test_proprietary_license_boundaries.sh
bash tools/test_coverage_policy.sh
bash tools/test_audit_ignore_policy.sh
bash tools/test_security_critical_dependencies_pinned.sh
bash tools/test_repo_truth.sh
bash tools/check_systemic_integrity_claims.sh
git diff --check
bash tools/ci_cargo_retry.sh cargo build --workspace --release
cargo test --workspace
cargo test --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit --deny unsound --deny unmaintained
cargo deny check
cargo tarpaulin --workspace --exclude exochain-wasm --exclude exochain-proofs --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90
```

Rediscover the current CI commands from `.github/workflows/ci.yml` on the actual
base and record any difference. A pre-existing failure is evidence, not a
waiver. Run these exact bypass guards:

```bash
! rg -n 'decision_forum::|ProtocolHash256|Ed25519VerificationKey|Ed25519Signature' crates/exo-gatekeeper/src/decision_forum_trust.rs
! rg -n 'pub fn (keys|resolve|root_map|new_verified|unchecked|verify_protocol_action_disposition)' crates/exo-gatekeeper/src/decision_forum_trust.rs crates/decision-forum/src/protocol
test "$(rg -n 'pub\(crate\) fn verify_protocol_action_disposition' crates/decision-forum/src/protocol/trust.rs | wc -l | tr -d ' ')" = 1
! rg -n 'AdjudicationContext|trusted_authority_keys|trusted_provenance_keys' crates/decision-forum/src/protocol/authority/qualification.rs
! rg -n 'HashMap|HashSet|\bf32\b|\bf64\b|SystemTime|Instant::now|Uuid::new_v4|thread_rng|rand::|unsafe[[:space:]]*\{' crates/decision-forum/src/protocol/authority crates/decision-forum/src/protocol/trust.rs crates/exo-gatekeeper/src/decision_forum_trust.rs crates/exo-gatekeeper/src/kernel.rs
! rg -n 'serde_json::to_(vec|string).*hash|receipt_root[[:space:]]*!=[[:space:]]*ProtocolHash256::ZERO' crates/decision-forum/src/protocol/authority
! git diff --name-only "$SLICE_BASE" "$IMPLEMENTATION_HEAD" | rg '(^|/)(migrations?|sql)/|crates/(exo-gateway|exochain-sdk|exo-node)/|packages/exochain-wasm|^(web|livesafe|crosschecked|cybermedica|command-base)/'
rg -n 'amendment_signature_message|D9_AMENDMENT_1_BLAKE3_HEX|Advisory|grants_authority' crates/decision-forum/src/constitution.rs crates/decision-forum/src/protocol/authority
```

Inventory REST, GraphQL, SDK, MCP, replay, idempotency, sibling route, and
cross-tenant ingress without editing them. State explicitly that Slice 4 owns
their stopped-protocol and persistence closure.

## Commit, PR, rollback, and evidence contract

- Use branch `bob-stewart/df-protocol-001-03-authority` and one draft PR only
  after separate operator authorization.
- Gates 00-09 each produce one coherent commit; Gate 10 produces its two listed
  commits; Gate 11 produces one evidence-only commit.
- Gatekeeper bootstrap, Decision Forum behavior, cross-implementation tooling,
  constitutional documents, evidence, runtime adapters, and proprietary paths
  never share a commit.
- The PR body records exact base/head/plan hashes, every path classification,
  domain and API inventories, trust/ratification boundary, RED/GREEN commands
  and logs, denominator/threshold proof, package-Chair proof, CAPA/RESET/
  promotion/notification substitution matrices, bypass analysis,
  `DF-001..DF-020` traceability, dependency/license truth, `Migrations: None`,
  rollback, external evidence hashes, and separate repository/CI/PR/deployment/
  runtime/ratification/credential/release/publication truth.
- Verify Apache-2.0 headers and notices on every new core source and Markdown
  file. Record byte equality for `Cargo.lock` and npm lockfiles.
- Rollback reverts Gate 10 through Gate 00 in reverse order, then reruns focused
  tests, both touched-crate suites, Slice 2 suites, domains/parity, source guards,
  and formatting. There is no schema/data/credential/deployment rollback because
  Slice 3 creates none.
- No implementation worker pushes, opens a PR, merges, signs, ratifies, issues
  credentials, deploys, or publishes without separate operator authorization.

## Literal bounded review/fixer/evidence loop

```yaml
loop:
  id: df-protocol-001-slice-3-review
  max_iterations: 12
  same_failure_limit: 2
  success_stop_condition: >-
    specification, technical, and whole-slice external reports all say APPROVED
    for the same implementation_head; immutable SHA-256 sidecars exist for each
    finalized report; one evidence-only direct child imports exact report and
    sidecar bytes plus a non-recursive manifest; allowed paths and clean status pass
  repeated_failure_escalation: >-
    stop automation and send the exact repeated finding identity, logs, base,
    and head to Bob Stewart as EXOCHAIN Chair/operator
  exhausted_loop_escalation: >-
    stop without approval and send all immutable iteration records to Bob
    Stewart as EXOCHAIN Chair/operator
```

The failure identity is `review_role + normalized_finding_id + owning_path +
failing_test`. The same identity twice stops the loop. Reviewer prose cannot
authorize another iteration.

Each report is uniquely named
`03-authority-role-iteration-NN-base-12sha-head-12sha.md` and contains role,
iteration, reviewed base/head, input hashes, inspected paths, rerun commands,
verdict, path/line/test evidence for every finding, downstream risks, and author
identity. It contains no digest of itself. After finalization:

```bash
REPORT="03-authority-${ROLE}-iteration-${NN}-base-${BASE12}-head-${HEAD12}.md"
test -f "$REPORT"
test ! -e "$REPORT.sha256"
shasum -a 256 "$REPORT" > "$REPORT.sha256"
shasum -a 256 -c "$REPORT.sha256"
chmod 0444 "$REPORT" "$REPORT.sha256"
test "$(stat -f '%Lp' "$REPORT")" = 444
test "$(stat -f '%Lp' "$REPORT.sha256")" = 444
```

`CHANGES_REQUIRED` freezes that head/report pair. A fresh fixer writes the
regression, makes the smallest owning-path correction, runs focused and affected
full gates, commits, and stops; both reviewers restart on the new complete
range. After three same-head approvals, the evidence importer copies exact
report and sidecar bytes into the mapped iteration directory and writes a
non-recursive manifest containing external/imported report and sidecar digests,
base, implementation head, and importer head. Mechanical closeout proves the
evidence commit is a direct child, contains only approved evidence/progress
paths, all hashes agree, and index/worktree/untracked status is empty. Any
behavior byte change restarts review on a new implementation head.

## DF-001 through DF-020 traceability

| Criterion | Slice 3 evidence and exact boundary |
|---|---|
| DF-001 | One canonical CBOR/domain hash path, 89-domain closed inventory, 42 new independent known-answer records, integer/BTree/HLC only |
| DF-002 | Every signed action commits its exact target; progressive, promotion, RESET, CAPA, EventClose, stop and notification substitutions fail |
| DF-003 | Immutable capability, identity/controller/authority/seat proof layers, fixed disjoint seats, exact controller/Co-PI/Chair exclusions |
| DF-004 | Fixed Council five and AI-IRB five; all four providers and two independent evidence classes; no recusal/absence shrinkage |
| DF-005 | Authorization dissent blocks; monitoring dissent alerts; exact package Chair; no manufactured stop |
| DF-006 | Exact D9 proof, individual kernel denial, Chair scoped hold, separate E-STOP threshold; absent ratification is advisory |
| DF-007 | Package-bound threshold/event, signed progressive decision, ordered next phase, exact envelope equality, Chair notice |
| DF-008 | Exact stop receipt/history, successor/constitution/prior chain, human investigator/AAR/RCA, CAPA, passed recurrence, dual-body target and Chair signature |
| DF-009 | Slice 3 supplies one pure stop authority result; Slice 4 owns all ingress and materialized bypass closure |
| DF-010 | Opaque trust outputs expose no root map/key and do not alter blind-custody/reveal transport |
| DF-011 | No CrossChecked change, dependency, fallback, vote, receipt, or core key |
| DF-012 | No UI/local actor/clock/random authority; Slice 6 owns the commercial control surface |
| DF-013 | Verified event, containment, exact package Chair, parallel typed requirements, signed CAPA, recurrence, EventClose |
| DF-014 | Apache-2.0/SPDX core paths only, byte-identical locks, no proprietary right by proximity |
| DF-015 | No evaluator/benchmark run or dogfood acceptance claim |
| DF-016 | Exact focused commands, API/compile-fail/doctest gates, full workspace/policy/parity/coverage gates |
| DF-017 | No persistence fallback/runtime activation claim; Slice 4 owns DAG DB degraded reads/writes |
| DF-018 | Pending E-STOP/promotion/CAPA/event results contain no fabricated receipt; Slice 4 owns atomic materialization |
| DF-019 | Ordered verified receipt facts and exact successor prior-chain commitment reject stale, broken, forked, replayed, and cross-tenant histories |
| DF-020 | No retrieval, compression, ranking, model judge, token, billing, savings, or DAG DB thesis dependency |

## Prior-audit closure matrix

| Finding | Required observable closure in the implementation plan |
|---|---|
| W2-01 | Both crates compile; Gatekeeper imports no downstream codec; capability has no public production constructor; ordinary and self-consistent attacker paths fail; no keys/maps escape |
| W2-02 | Existing amendment-domain signatures pass; cross-domain amendment/receipt signatures fail; exact byte/Article/corpus mutation fields match both frozen tables |
| W2-03 | Package/root/Chair-derived monitoring retains exact definitions/destinations/domains; progressive target commits event, plan, threshold, evidence and result |
| W2-04 | Opaque full envelope and ordered ladder plus exact progressive-decision hash; every adjacency/envelope mutation fails |
| W2-05 | Exact root and non-optional trust registry verify every E-STOP vote before counting; absence compile-fails; wrong supplied registries fail runtime |
| W2-06 | Exact human producers, ordered stop history, successor package/constitution/prior-chain witness, and one RESET target shared by all signers |
| W2-07 | Owner-signed CAPA open/complete, exact receipt, independently rooted recurrence, context-only learning, separate EventClose target |
| W2-08 | Exact package Chair and complete typed requirements for dissent, adverse, transgression, E-STOP, and promotion; deliveries independent |
| W2-09 | Exhaustive file map, all API pointers/raw inputs/errors, private-field/package-private/missing-registry compile failures, complete Gates 09/10 |
| W2-10 | Reports exclude own digest; immutable sidecars and non-recursive import manifest carry every digest |
| W3-01 | `verify_stop_continuation` derives all claimed facts from exact opaque package boundaries and ordered signed-receipt facts |
| W3-02 | Row-40 RESET target commits every prerequisite and signer identity/eligible set; all three authorities bind the same hash; human producers compile |
| W3-03 | Progressive body target commits exact event/monitoring/threshold/observation result; promotion body target commits exact progressive-decision hash |
| W3-04 | 42 exact variants/strings/canonical values are in `domains.rs`, `ALL == 89` (47 Slice 2 + 42 Slice 3), and independent known-answer vectors cover all rows |
| W3-05 | `authority/mod.rs` and `df_protocol_001_dissent_chair.rs` are mapped; Gate 00 compile/visibility and Gates 09/10 exact commands/code are present |
| W3-06 | Public byte mutations expect exact BLAKE3 fields; internal derived-Article mutations expect `article_mapping`; every other field is explicit |
| W3-07 | Monitoring rejects non-Chair escalation DID and constructs typed Chair only from the package-bound opaque Chair proof |
| W3-08 | Missing registry is compile-fail only; runtime matrix supplies wrong opaque registries without weakening the production signature |

## Final author self-review

- Re-read all 790 canonical-design lines and the frozen Slice 2 interfaces at
  the actual base; map every Slice 3 requirement to one gate and test.
- Confirm every public symbol has exactly one owner and every receiver,
  visibility, parameter, return, domain, signing payload, and error matches this
  brief.
- Confirm opaque proofs have private fields, no public/production-test
  constructor, no serialization, and no clone unless the type's duplication is
  harmless and proven.
- Confirm no package, roster, candidate key, root map, raw receipt, phase string,
  CAPA, event, learning record, human label, generic digest, or raw Chair DID can
  mint authority.
- Confirm `ProtocolHashDomain::ALL` has the frozen 47 Slice 2 variants followed
  by exactly the 42 Wave 4 variants and that both implementations execute every
  known-answer input independently.
- Confirm body signatures bind the exact progressive, EventClose, promotion,
  and RESET targets; Chair RESET signs the same row-40 hash as both bodies.
- Confirm exact nine-field E-STOP separation, checked ceiling, fixed five-seat
  denominators, provider/evidence floors, package Chair routing, and advisory
  behavior without D9 ratification.
- Confirm every gate contains RED code, exact command, expected error/failure,
  complete minimum GREEN, affected suite, staged paths, and commit.
- Confirm licenses, rollback, finite loop, non-recursive report hashing, path
  boundary, and separate truth claims are complete.
- Obtain fresh specification, technical, and whole-slice approval for the same
  implementation head before importing evidence or claiming Slice 3 acceptance.


---

## Plan-document self-validation (planning RED before implementer dispatch)

These checks validate **this plan document** only. They do not compile production
crates and do not claim implementation GREEN.

```bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
PLAN="$ROOT/docs/superpowers/plans/2026-07-16-df-protocol-001-03-council-ai-irb-stop-authority.md"
S1="$ROOT/docs/superpowers/plans/2026-07-16-df-protocol-001-01-charter-normative-schema.md"
S2="$ROOT/docs/superpowers/plans/2026-07-16-df-protocol-001-02-core-protocol-receipt-model.md"

test "$(shasum -a 256 "$S1" | awk '{print $1}')" = "4e3a97540dae01dbe0b9ae9b162fc225a67e5f51d2072762f19d901c123ea081"
test "$(shasum -a 256 "$S2" | awk '{print $1}')" = "fa804fefdb56d9595afc6517923bb2316b6b3917ddae3a6110cf41f03036fb22"
test -f "$PLAN"

rg -q --fixed-strings "VerifiedEligibleUnanimityDecisionV1" "$PLAN"
rg -q --fixed-strings "evaluate_estop" "$PLAN"
rg -q --fixed-strings "evaluate_reset" "$PLAN"
rg -q --fixed-strings "evaluate_phase_promotion" "$PLAN"
rg -q --fixed-strings "authority/estop.rs" "$PLAN"
rg -q --fixed-strings "df_protocol_001_estop.rs" "$PLAN"
rg -q --fixed-strings "ALL.len(), 89" "$PLAN"
rg -q --fixed-strings "ALL[47..]" "$PLAN"
rg -q --fixed-strings "fa804fefdb56d9595afc6517923bb2316b6b3917ddae3a6110cf41f03036fb22" "$PLAN"
rg -q --fixed-strings "Gate 00" "$PLAN"
rg -q --fixed-strings "Gate 11" "$PLAN"
rg -q --fixed-strings "PendingNotificationRequirementV1" "$PLAN"
rg -q --fixed-strings "Wave 20 / Slice 2 reconciliation" "$PLAN"
rg -q --fixed-strings "89-domain inventory" "$PLAN"

python3 - "$PLAN" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text()
markers = sum(1 for line in text.splitlines() if line.strip().startswith("`" * 3))
if markers % 2 != 0:
    raise SystemExit(f"unbalanced fences markers={markers}")

patterns = [
    re.compile("68" + "-domain"),
    re.compile(r"ALL == " + "68"),
    re.compile(r"ALL\.len\(\), " + "68"),
    re.compile(r"ALL\[" + "26" + r"\.\."),
]
bad = []
for lineno, line in enumerate(text.splitlines(), 1):
    if "prescribed extension to **68**" in line or ", not 68" in line:
        continue
    if "re.compile" in line or "patterns =" in line:
        continue
    if "prescribed extension" in line and "68" in line:
        continue
    for pat in patterns:
        if pat.search(line):
            bad.append((lineno, line.strip()[:160]))
            break
if bad:
    for item in bad:
        print(item, file=sys.stderr)
    raise SystemExit("residual Wave-4 domain inventory contracts")
print("fences_ok domain_residue_ok")
PY

echo "slice3_plan_self_validation=GREEN"
```

### Plan SHA-256 (recompute after every edit)

```bash
shasum -a 256 docs/superpowers/plans/2026-07-16-df-protocol-001-03-council-ai-irb-stop-authority.md
```
