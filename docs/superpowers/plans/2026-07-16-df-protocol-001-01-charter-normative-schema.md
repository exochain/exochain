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

# DF-PROTOCOL-001 Charter and Normative Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task by task.
> Every behavior or document contract begins with an observed RED test or
> deterministic source guard. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the content-addressed D9 Amendment 1 proposal, its explicitly
nonbinding ratification manifest, the reviewed `PeerReviewedProtocolPackageV1`
JSON transport schema, and threat/traceability records without modifying the
frozen D9 proposal or enabling binding Council/AI-IRB behavior.

**Architecture:** The frozen D9 bytes remain the immutable predecessor. A new
proposal document carries constitutional role, quorum, envelope, stop/reset,
and finite-loop rules; a separate manifest content-addresses those bytes while
recording that ratification, credentials, and binding mode are absent. A JSON
Schema fixes the transport projection and exact cross-slice field names while
the authoritative representation remains domain-separated canonical CBOR in
slice 2. A Rust integration source guard reads repository governance artifacts
at test time so every document/schema change is test-first and the published
crate does not embed governance files.

**Tech Stack:** Markdown constitutional proposal, JSON Schema draft 2020-12,
Rust integration tests using `serde_json`, `blake3`, and the repository-locked
`jsonschema` 0.19.1 validator, existing EXOCHAIN governance
threat/traceability matrices, `cargo`, `jq`, and `b3sum` for evidence capture.

## Global Constraints

- The frozen file `governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md` must
  remain byte-identical with BLAKE3
  `c1e89db47a30849d41e6db9c4c23d52d9dfbf3a820f2695dcdbcade6d42bd6af`.
- D9 Amendment 1 remains `PROPOSED`, not ratified and not enacted. The manifest
  must set `binding_mode_allowed` to `false` with empty ratification and
  credential-attestation receipt arrays.
- Bob Stewart is the human Co-PI and Chair; Codex is the AI Co-PI authorship
  role. Neither role statement creates a DID, credential, signature, seat, or
  binding authority.
- The Council eligible set is OpenAI, Anthropic, xAI, Alphabet/Google Gemini,
  and one independent non-provider seat. AI-IRB has the same composition under
  separate DIDs, keys, context manifests, assignments, and attestations. The
  Chair is ex officio and outside both five-seat denominators.
- Binding authorization requires all five eligible Council approvals, all
  five eligible AI-IRB approvals, all four provider classes, and at least two
  genuinely independent evidence classes including the non-provider class.
  `ProviderModelJudgment` remains valid non-binding inventory evidence but is
  impossible in a binding or E-STOP independent-evidence set. Missing,
  unavailable, recused, expired, changed, or conflicted seats never shrink the
  ratified denominator or floor.
- Chair approval cannot manufacture Council/AI-IRB unanimity. Chair rejection
  is a scoped HumanOverride hold. RESET requires human-attested AAR and RCA,
  completed CAPA, deterministic recurrence evidence, unanimous eligible
  Council, unanimous eligible AI-IRB, and the Chair signature.
- Every autonomous evaluation declares a positive `max_iterations` no greater
  than 25, a concrete success stop, repeat-failure stop after the same failure
  twice, and an escalation destination.
- Authoritative values use integers, basis points, `BTreeMap`/`BTreeSet`,
  caller-supplied identifiers, HLC timestamps, canonical CBOR, and
  domain-separated BLAKE3. No authoritative JSON hashing, floating point,
  system/browser wall clock, random governance identifier, `HashMap`,
  `HashSet`, unsafe code, or production `unwrap`/`expect` is allowed.
- `PeerReviewedProtocolPackageV1` is the authority object. JSON is a transport
  projection only. Slice 1 creates no production Rust type, database migration,
  route, UI, credential, signature, runtime activation, or publication.
- DAG DB is required persistence infrastructure, but retrieval quality,
  compression, similarity, ranking, token savings, and economic-thesis work is
  excluded from this implementation program and may appear only in the
  separate `DF-ROADMAP-001` research record.
- `crates/decision-forum` and generic schema primitives remain Apache-2.0.
  Decision Forum product UI/operating assets, CrossChecked, CyberMedica,
  LegalDyne, and LiveSafe remain commercially licensed and gain no
  constitutional trust by proximity.
- Imported reports, screenshots, archives, generated scans, and consultant
  artifacts remain read-only evidence and are not committed as source.

---

## Scope and file classification

| Path | Change | Classification | Exact staging / commit boundary |
|---|---|---|---|
| `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md` | Create | EXOCHAIN core constitutional governance artifact | Task 1 amendment commit |
| `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json` | Create | EXOCHAIN core constitutional governance artifact | Task 3 manifest commit |
| `governance/schemas/peer-reviewed-protocol-package-v1.schema.json` | Create | EXOCHAIN core normative transport schema | Task 2 schema commit |
| `crates/decision-forum/tests/df_protocol_001_normative_contract.rs` | Create | EXOCHAIN core deterministic source guard | Staged explicitly in Tasks 1-4 as each RED/GREEN guard grows |
| `crates/decision-forum/Cargo.toml` | Modify | EXOCHAIN core test dependency configuration; add exact `jsonschema` 0.19.1 and workspace-pinned `ed25519-dalek` dev dependencies | Task 2 schema commit |
| `Cargo.lock` | Modify | EXOCHAIN core reproducible dependency graph; add the already-locked validator to the Decision Forum package dependency list | Task 2 schema commit |
| `governance/threat_matrix.md` | Modify | EXOCHAIN core governance documentation | Task 4 threat/traceability commit |
| `governance/traceability_matrix.md` | Modify | EXOCHAIN core governance documentation | Task 4 threat/traceability commit |
| `tools/cross-impl-test/compare.sh` | Modify | EXOCHAIN core CI/test tool; compare real per-vector Rust and TypeScript outputs in temporary directories | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/compare_unit_test.sh` | Modify | EXOCHAIN core CI/test-tool regression guard | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/index.js` | Delete | EXOCHAIN core CI/test tool; replaced in place rather than retaining a parallel JavaScript runner | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/index.ts` | Create | EXOCHAIN core CI/test tool; pinned TypeScript vector executor | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/package.json` | Modify | EXOCHAIN core CI/test-tool dependency and script contract | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/package-lock.json` | Modify | EXOCHAIN core reproducible TypeScript dependency graph | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/tsconfig.json` | Create | EXOCHAIN core CI/test-tool compiler contract | Task 5 isolated cross-implementation hardening commit |
| `tools/cross-impl-test/vectors/hash_blake3.json` | Create | EXOCHAIN core committed cross-implementation input vector | Task 5 isolated cross-implementation hardening commit |
| `crates/exo-core/tests/cross_impl_hash_vectors.rs` | Modify | EXOCHAIN core Rust vector executor and normalized-output writer | Task 5 isolated cross-implementation hardening commit |
| `.superpowers/sdd/progress.md` | Modify | Tracked implementation-orchestration evidence ledger | Initial entry is committed with the immutable base before Task 1 RED; later results use append-only evidence commits; preserve all pre-existing programs |
| `.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha` | Create | Tracked implementation evidence containing the immutable task base plus newline | Evidence-control commit before Task 1 RED; never overwritten |
| `.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-implementer.md` | Create | Tracked implementation report with RED/GREEN, gate, commit-range, and concern evidence | Task 6 evidence commit after independent approval |

**Database migrations:** None. Any migration, SQL, gateway route, persistence
service, or production behavior in this slice is a scope violation.

**PR boundary:** Implement on
`bob-stewart/df-protocol-001-01-charter-schema` after the complete plan set is
approved. Submit one slice PR with isolated documentation/core-governance and
core CI/test-tool commits. Do not combine this slice with slice 2 Rust
production types or any proprietary surface change. The one required core
CI/test-tool hardening concern stays in its own Task 5 commit and is classified
separately from the amendment/schema commits.

## Interfaces fixed for downstream slices

The schema uses snake-case JSON keys matching the future Rust fields. Slice 2
must either implement these exact fields or amend this reviewed schema through
the same content-addressed review process.

```rust
pub struct PeerReviewedProtocolPackageV1 {
    pub schema_version: u16,
    pub protocol_identity: ProtocolIdentity,
    pub protocol_document: ProtocolDocument,
    pub protocol_envelope: ProtocolEnvelope,
    pub evidence_manifest: EvidenceManifest,
    pub review_bundle: ReviewBundle,
    pub disposition_bundle: DispositionBundle,
    pub monitoring_plan: MonitoringPlan,
    pub systemic_learning_manifest: SystemicLearningManifest,
    pub commercial_boundary: CommercialBoundary,
    pub receipt_manifest: ReceiptManifest,
}

/// Complete evidence inventory vocabulary. Provider/model judgment is
/// preserved here for non-binding provenance and seat evidence only.
pub enum EvidenceClass {
    ProviderModelJudgment,
    DeterministicTest,
    ReproducibleBenchmark,
    AttestedExecution,
    IndependentHumanReview,
    FormalVerification,
    ExternalAudit,
    IndependentNonProviderEvidence,
}

/// Closed vocabulary for fields that satisfy a binding or E-STOP independent-
/// evidence floor. ProviderModelJudgment is intentionally unrepresentable.
pub enum IndependentEvidenceClass {
    DeterministicTest,
    ReproducibleBenchmark,
    AttestedExecution,
    IndependentHumanReview,
    FormalVerification,
    ExternalAudit,
    IndependentNonProviderEvidence,
}

pub struct EvidenceManifest {
    pub items: Vec<HashReference>,
    pub independent_evidence_classes: BTreeSet<IndependentEvidenceClass>,
    pub negative_or_inconclusive_results: Vec<HashReference>,
}

pub struct QuorumProof {
    pub proof_id: Uuid,
    pub seat_kind: SeatKind,
    pub eligible_seat_hashes: BTreeSet<Hash256>,
    pub approve_seat_hashes: BTreeSet<Hash256>,
    pub provider_classes: BTreeSet<ProviderClass>,
    pub evidence_classes: BTreeSet<IndependentEvidenceClass>,
    pub eligible_count: u8,
    pub approve_count: u8,
    pub required_count: u8,
    pub result: QuorumResult,
    pub computed_at: Timestamp,
    pub proof_hash: Hash256,
}

pub struct EstopAuthorization {
    pub estop_id: Uuid,
    pub scope_hash: Hash256,
    pub active_provider_classes: BTreeSet<ProviderClass>,
    pub approve_provider_classes: BTreeSet<ProviderClass>,
    pub required_provider_class_count: u8,
    pub independent_evidence_classes: BTreeSet<IndependentEvidenceClass>,
    pub threshold_result: EstopThresholdResult,
    pub fired_at: Timestamp,
    pub receipt_root: Hash256,
}

/// Created only after schema validation, semantic validation, signature and
/// authority resolution, predecessor-chain verification, and exact
/// normalized-final-root recomputation all succeed. Its fields are private;
/// callers cannot construct it from request or stored projection data.
pub struct VerifiedPackageRoot {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: Hash256,
    final_package_root: Hash256,
}

/// Output of prior kernel adjudication plus authority-chain verification.
/// Decision Forum consumes this trusted result; it never builds expected
/// signer authority from the package or receipt chain under review.
pub struct VerifiedAuthorityRegistryV1 {
    entries: BTreeMap<(Did, AuthorityScope), VerifiedAuthorityBindingV1>,
}

pub struct VerifiedAuthorityBindingV1 {
    tenant_id: TenantId,
    protocol_id: ProtocolId,
    actor_did: Did,
    scope: AuthorityScope,
    signing_key_id: Hash256,
    verification_key: Ed25519VerificationKey,
    authority_chain_hash: Hash256,
}

/// Opaque output of prior identity, authority-chain, seat-controller, and
/// kernel verification. It is built before package parsing and cannot be
/// constructed from any `PeerReviewedProtocolPackageV1` field.
pub struct VerifiedSeatAuthorityRegistryV1 {
    entries: BTreeMap<(Did, SeatKind), VerifiedSeatAuthorityBindingV1>,
}

pub struct VerifiedSeatAuthorityBindingV1 {
    tenant_id: TenantId,
    protocol_id: ProtocolId,
    seat_did: Did,
    seat_kind: SeatKind,
    provider_class: ProviderClass,
    controller_did: Did,
    seat_signing_key_id: Hash256,
    seat_verification_key: Ed25519VerificationKey,
    controller_signing_key_id: Hash256,
    controller_verification_key: Ed25519VerificationKey,
    context_manifest_hash: Hash256,
    seat_attestation_hash: Hash256,
    valid_from: Timestamp,
    valid_until: Timestamp,
    independent_control_proof_hash: Option<Hash256>,
    authority_scope: AuthorityScope,
    verified_authority_chain_hash: Hash256,
}

pub trait VerifiedAuthorityResolverV1 {
    fn resolve(
        &self,
        tenant_id: &TenantId,
        protocol_id: &ProtocolId,
        actor_did: &Did,
        scope: AuthorityScope,
    ) -> Result<&VerifiedAuthorityBindingV1, AuthorityResolutionError>;
}

pub trait VerifiedExecutionAuthorityV1 {
    fn create_execution_receipt_chain(
        verified_root: &VerifiedPackageRoot,
        verified_predecessor: Option<&VerifiedExecutionChain>,
        authority_registry: &VerifiedAuthorityRegistryV1,
        request: CreateExecutionReceiptChain,
    ) -> Result<ProtocolExecutionReceiptChainV1, DecisionForumError>;

    fn authorize_governed_action(
        verified_root: &VerifiedPackageRoot,
        authority_registry: &VerifiedAuthorityRegistryV1,
        request: GovernedActionRequest,
    ) -> Result<AuthorizedGovernedAction, DecisionForumError>;
}

pub const PEER_REVIEWED_PROTOCOL_PACKAGE_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.peer_reviewed_protocol_package.v1";
pub const PROTOCOL_AUTHORIZATION_TARGET_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.protocol_authorization_target.v1";
pub const PEER_REVIEW_SIGNING_PAYLOAD_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.peer_review_signing_payload.v1";
pub const SEAT_ATTESTATION_SIGNING_PAYLOAD_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.seat_attestation_signing_payload.v1";
pub const COUNCIL_DISPOSITION_SIGNING_PAYLOAD_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.council_disposition_signing_payload.v1";
pub const AI_IRB_DISPOSITION_SIGNING_PAYLOAD_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.ai_irb_disposition_signing_payload.v1";
pub const CHAIR_INTERVENTION_SIGNING_PAYLOAD_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.chair_intervention_signing_payload.v1";
pub const PREPUBLICATION_PACKAGE_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.prepublication_package.v1";
pub const PUBLICATION_AUTHORIZATION_RECEIPT_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.publication_authorization_receipt.v1";
pub const PUBLICATION_ARTIFACT_MANIFEST_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.publication_artifact_manifest.v1";
pub const PROTOCOL_EXECUTION_RECEIPT_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.protocol_execution_receipt.v1";
pub const PROTOCOL_EXECUTION_RECEIPT_CHAIN_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.protocol_execution_receipt_chain.v1";
pub const GENESIS_EVIDENCE_BUNDLE_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.genesis_evidence_bundle.v1";
pub const GENESIS_ADOPTION_RECEIPT_V1_HASH_DOMAIN: &str =
    "exo.decision_forum.genesis_adoption_receipt.v1";
pub const FINAL_PACKAGE_ROOT_NORMALIZATION: &str =
    "replace receipt_manifest.final_package_root with 32 zero bytes";
```

The JSON projection represents `Hash256` as 64 lowercase hexadecimal
characters, Git provenance as a typed `{ algorithm: "sha1", digest: <40
lowercase hexadecimal characters> }` object, `Did` as
`did:exo:<method-specific>`, caller-supplied UUIDs as canonical lowercase UUID
strings, and `Timestamp` as `{ physical_ms: u64, logical: u32 }` including
`Timestamp::ZERO`. Authoritative maps and sets become sorted JSON projections
but are rebuilt as `BTreeMap`/`BTreeSet` before canonical CBOR hashing.

Resource ceilings are a typed plural map keyed by the closed `ResourceKind`
vocabulary and valued in nonnegative `u64` integer units. Council and AI-IRB
dispositions are separate signed types: each commits one common
`authorization_target_hash`, protocol version, review bundle, eligible set,
seat attestation, context manifest, choice, and a body-specific Ed25519
signature envelope. Review rosters are closed objects with exactly the keys
`openai`, `anthropic`, `xai`, `alphabet_google_gemini`, and
`independent_non_provider`; each value carries the seat DID and the
body-specific attestation. This structurally fixes the provider composition,
while the semantic validator proves cross-field DID set equality and
Council/AI-IRB separation.

`EvidenceClass` is the complete evidence-inventory vocabulary and therefore
retains `ProviderModelJudgment` for non-binding provider/seat provenance.
Every field used to satisfy an independent evidence floor instead uses the
closed `IndependentEvidenceClass`: `EvidenceManifest.independent_evidence_classes`,
`QuorumProof.evidence_classes`, and
`EstopAuthorization.independent_evidence_classes`. The latter type excludes
`ProviderModelJudgment`; transport decoding into a binding Rust object must
fail before semantic verification if that value appears in any of those
fields. Semantic verification rebuilds each as an exact
`BTreeSet<IndependentEvidenceClass>` and requires each quorum proof set to
equal the package manifest set.

Every seat attestation exposes the exact `signing_key_id` and Ed25519
`verification_key` authorized for that seat, but those in-package values are
claims, never trust anchors. Before package parsing, identity,
authority-chain, controller-independence, validity, and kernel verification
produce an opaque `VerifiedSeatAuthorityRegistryV1`. Its ten entries bind the
tenant and protocol; seat DID and Council/AI-IRB body; provider class and
controller DID; seat key ID and verification key; controller key ID and
verification key; exact context-manifest and complete signed-attestation
hashes; validity interval; independent-control proof when applicable; and
verified authority scope and chain hash. No constructor accepts a package,
roster, attestation, assignment, review, or vote.

`SeatAttestation` carries a typed Ed25519 envelope over exact canonical CBOR of
`SeatAttestationSigningPayloadV1`, which is every attestation field except the
signature. The envelope domain is
`exo.decision_forum.seat_attestation_signing_payload.v1` and target is
`SeatAttestationV1`. Verification resolves the controller key only from
`VerifiedSeatAuthorityRegistryV1`, recomputes the payload digest and complete
attestation hash, verifies the controller signature, checks the validity
interval against the caller-supplied verification HLC, and requires every
tenant/protocol/seat/body/provider/controller/key/context/proof/scope/chain
fact to equal the independent binding. Peer-review and Council/AI-IRB vote
verification then resolve seat keys only from the same registry, never from
the package attestation. The four provider seats and the independent seat use
distinct keys and contexts in Council and AI-IRB. The publisher retains a
separately typed `PublisherAuthorityV1` record resolved through
`VerifiedAuthorityRegistryV1`.

`DispositionBundle.authority_chain` is not an array of opaque content
references. It is a typed, closed array of exactly twelve
`AuthorityChainReferenceV1` values for the ten seat bindings, Chair, and
publisher. Every reference includes binding kind and controller DID, and must
exactly equal its independently verified registry binding. Execution signers
live in the external execution chain and likewise resolve only through
`VerifiedAuthorityRegistryV1`; they are not invented as in-package actors.
Replacing every seat DID, key, controller, authority chain, attestation,
review, vote, proof, publication receipt, and package root and then validly
re-signing/re-hashing the attacker-controlled graph still fails against the
unchanged registries.

### Acyclic package and execution-receipt construction

Slice 2 implements these exact package steps and slice 4 implements the
external execution chain. The schema, nonempty slice 1 fixtures, and
cross-implementation vectors name them now so later code cannot invent a
circular or partial commitment:

1. `AuthorizationTargetV1` is canonical CBOR of exactly
   `schema_version`, `protocol_identity`, `protocol_document`,
   `protocol_envelope`, `evidence_manifest`, and the complete review content
   in `review_bundle` after normalizing only each
   `signed_reviews[*].authorization_target_hash` and
   `signed_reviews[*].signature.signed_payload_hash` to 32 zero bytes and
   `signed_reviews[*].signature.signature` to 64 zero bytes,
   `monitoring_plan`, `systemic_learning_manifest`, `commercial_boundary`,
   `receipt_manifest.preauthorization_lifecycle_receipts`,
   `receipt_manifest.prior_execution_receipt_chain`, and
   `receipt_manifest.genesis_adoption_receipt`. It excludes the entire
   `disposition_bundle`, `publication_authorization_receipt`, and
   `final_package_root`. Review assignments, criteria/content hashes,
   responses, revision diffs, resolutions, conflicts, commitments, and reveal
   remain included exactly. Hash domain:
   `exo.decision_forum.protocol_authorization_target.v1`. The normalized
   signature envelope retains its algorithm, signing-key identifier,
   verification key, and body-specific `PeerReviewV1` target so the key and
   signature type remain committed before the common target is calculated.
   After that target is fixed, each reviewer signs a body-specific canonical
   `PeerReviewSigningPayloadV1` containing exactly `review_id`,
   `assignment_id`, `protocol_version_hash`, `criteria_results_hash`,
   `review_body_hash`, `disposition`, `sealed_at`, and the common
   `authorization_target_hash`. Its BLAKE3 domain is
   `exo.decision_forum.peer_review_signing_payload.v1`; the resulting digest
   must equal `signature.signed_payload_hash`, the Ed25519 signature must
   verify over that digest, `signature.signed_payload_target` must be
   `PeerReviewV1`, and `signature.signing_key_id` must resolve through the
   assignment to that reviewer's independently verified
   `VerifiedSeatAuthorityRegistryV1` key. The in-package attestation is first
   matched in full and controller-signature-verified against that registry,
   but never supplies the verification key. Council and AI-IRB
   voters bind the same common authorization target in body-specific payloads
   containing every disposition field except the signature. Their respective
   domains are `exo.decision_forum.council_disposition_signing_payload.v1` and
   `exo.decision_forum.ai_irb_disposition_signing_payload.v1`. Each Chair
   intervention is independently signed over the complete
   `ChairInterventionSigningPayloadV1` body (every intervention field except
   `signature`) under
   `exo.decision_forum.chair_intervention_signing_payload.v1`; its Chair DID,
   key ID, verification key, scope hash, choice, and effect resolve against
   the package's `ChairAuthorityV1` and exact protocol-envelope hash. No
   review, disposition, or Chair intervention signs a container that contains
   itself.
2. `PrepublicationPackageV1` is canonical CBOR of the complete package after
   dispositions are fixed, with
   `receipt_manifest.publication_authorization_receipt` normalized to CBOR
   `null` and `receipt_manifest.final_package_root` normalized to exactly 32
   zero bytes. It includes all other in-package receipts and the complete
   `DispositionBundle`. Hash domain:
   `exo.decision_forum.prepublication_package.v1`.
3. `PublicationAuthorizationReceiptV1` is an in-package signed receipt over
   exactly `prepublication_root`, `renderer_manifest_hash`, `publisher_did`,
   and `authorized_at`. Hash domain:
   `exo.decision_forum.publication_authorization_receipt.v1`. Its signature
   verifies over canonical CBOR of exactly those four fields and its
   `signing_key_id` plus `verification_key` resolve to the separately typed
   publisher authority. It authorizes a pinned renderer configuration for
   those prepublication bytes; it does not claim the later projection digests.
4. The authoritative final package root is BLAKE3 over domain
   `exo.decision_forum.peer_reviewed_protocol_package.v1` and canonical CBOR
   of the complete Approved package, including every disposition and every
   allowed in-package preauthorization/lifecycle or predecessor-chain receipt
   commitment (including `PublicationAuthorizationReceiptV1`), after replacing
   only `receipt_manifest.final_package_root` with exactly 32 zero bytes.
   Verification repeats that normalization and requires the recomputed digest
   to equal the stored `final_package_root`. Only then does the verifier return
   the opaque `VerifiedPackageRoot`. Execution-chain creation and action
   authorization accept only `&VerifiedPackageRoot`; no interface accepts a
   raw stored root or a `PeerReviewedProtocolPackageV1` in its place. This
   single-field normalization is the only excluded value.

The Approved package MUST NOT contain an action, event, continuing-review, or
other post-authorization receipt whose `authorized_package_root` is that same
package's final root. Its in-package `preauthorization_lifecycle_receipts`
have `authorized_package_root: null` and cover only milestones through
`Approved`. For version 1, both `protocol_identity.prior_version_hash` and
`prior_execution_receipt_chain` are `null`. For every version greater than or
equal to 2, both fields are non-null and the receipt field is a
`PriorExecutionReceiptChainReferenceV1` that commits the exact predecessor
tenant, protocol ID, protocol-version hash, authorized package root,
predecessor-chain root/hash/sequence, first sequence, terminal receipt hash,
terminal sequence, and receipt count. `protocol_identity.prior_version_hash` equals the
reference's `prior_protocol_version_hash`; it is not overloaded with the
predecessor package root. Verification reconstructs the referenced predecessor
chain and requires exact equality for every one of those fields before the
successor package can bind it. Thus an in-package prior-receipt mutation
changes the successor authorization target and final root.

Current post-authorization execution and monitoring records live only in the
external immutable `ProtocolExecutionReceiptChainV1`. All segments belong to
one tenant/protocol DAG DB subject history, matching `dagdb_receipts` and
`dagdb_subject_receipt_heads`: the first/genesis segment has no predecessor,
starts at sequence 1, and links its first receipt to `Hash256::ZERO`; every
continuation starts at predecessor `terminal_sequence + 1` and its first
receipt's previous hash equals the predecessor terminal receipt hash. Every
nonempty chain
names the exact tenant, protocol ID, protocol-version hash, and already-fixed
current `final_package_root`; every `ProtocolExecutionReceiptV1` repeats all
four values, is independently Ed25519-signed over its complete body under domain
`exo.decision_forum.protocol_execution_receipt.v1`, and links by the hash of
the previous signed receipt. `first_sequence`, `terminal_sequence`, and
`receipt_count` describe a continuous interval. The first receipt links to the
predecessor chain's terminal receipt hash while `previous_chain_root`,
`predecessor_terminal_receipt_hash`, and `predecessor_terminal_sequence` name
that exact predecessor state. The chain root is the domain-separated canonical-CBOR hash of
the complete chain after normalizing only `chain_root` to 32 zero bytes. A
reset, gap, duplicate, changed receipt body, signature, link, sequence, wrong
terminal, or replay either fails
verification or changes the external chain root. Only a successor package may
commit that completed root through `prior_execution_receipt_chain`; a chain
never appears in the package whose root it authorizes.

`GenesisEvidenceBundleV1` is a pre-activation-only object containing typed Git
object IDs, a chronology-manifest hash, and a historical-review-evidence hash.
Its domain-separated hash is
`exo.decision_forum.genesis_evidence_bundle.v1`; it has no field capable of
naming the current package, authorization target, prepublication root, or
final package root. `GenesisAdoptionReceipt` commits that bundle hash and its
own prospective effect. Its `receipt_root` is recomputed under
`exo.decision_forum.genesis_adoption_receipt.v1` after normalizing only
`receipt_root` to 32 zero bytes. Semantic validation additionally rejects any
genesis string field that equals the current authorization target,
prepublication root, or final package root. This preserves pre-activation
chronology without a current-root cycle or retroactive signature claim.

`DeterministicArtifactManifestV1` is outside the package and cannot create an
indirect cycle. It contains the final package root, pinned renderer-manifest
hash, and deterministic CBOR/Markdown/HTML/PDF-A projection digests; its own
domain is `exo.decision_forum.publication_artifact_manifest.v1`. Verification
first validates the final package root and in-package publication
authorization, then recomputes every external artifact digest. A changed
protocol/document/envelope/evidence/review/monitoring/commercial/prior link
changes the authorization target. A changed disposition or any in-package
preauthorization or predecessor-chain receipt changes the prepublication or
final root. A changed current external receipt fails its signature/link or
changes the current external chain root, which the next package commits. A
changed renderer manifest
changes the publication receipt and final root. A changed post-root projection
changes or invalidates only the external artifact manifest; it can never
silently rewrite execution authority.

### Recorded task-base contract

Begin in a dedicated clean slice worktree. Before any Task 1 test file is
written, create the evidence directory, record the current head exactly once,
validate it, append the initial ledger entry, and immediately commit both
evidence-control files. Reload that same immutable value for every later range
check:

```bash
REPORT_DIR=.superpowers/sdd/reports/df-protocol-001
TASK_BASE_FILE="$REPORT_DIR/01-charter-normative-schema-task-base.sha"
IMPLEMENTER_REPORT="$REPORT_DIR/01-charter-normative-schema-implementer.md"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
mkdir -p "$REPORT_DIR"
test ! -e "$TASK_BASE_FILE"
git rev-parse HEAD > "$TASK_BASE_FILE"
TASK_BASE="$(tr -d '\n' < "$TASK_BASE_FILE")"
test "$(printf '%s' "$TASK_BASE" | wc -c | tr -d ' ')" -eq 40
git cat-file -e "$TASK_BASE^{commit}"
git merge-base --is-ancestor "$TASK_BASE" HEAD
printf 'DF-PROTOCOL-001 slice 1: started (task base %s)\n' "$TASK_BASE" >> .superpowers/sdd/progress.md
git add .superpowers/sdd/progress.md "$TASK_BASE_FILE"
git diff --cached --check
git commit -m "docs(governance): record DF slice task base"
test "$(git show HEAD:"$TASK_BASE_FILE" | tr -d '\n')" = "$TASK_BASE"
test "$(git show HEAD:.superpowers/sdd/progress.md | tail -n 1)" = \
  "DF-PROTOCOL-001 slice 1: started (task base $TASK_BASE)"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Expected: every command exits 0; the dedicated worktree is clean before and
after; the base file contains exactly one 40-character Git SHA-1 object ID plus
a newline and is immutable in the isolated evidence-control commit; and the
initial ledger entry is committed before any RED test. The implementer must
never overwrite the base file or substitute a moving `origin/main` merge base.
Every subsequent range command begins by reloading and revalidating `TASK_BASE`
from the committed file.

### Task 1: Freeze D9 and add the non-enacted Amendment 1 proposal

**Files:**

- Create: `crates/decision-forum/tests/df_protocol_001_normative_contract.rs`
- Create: `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md`
- Verify unchanged: `governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md`
- Verify unchanged: `governance/proposals/SEAT-000-COORDINATOR-RECORD.md`

**Interfaces:**

- Consumes: frozen D9 BLAKE3 and the canonical DF-PROTOCOL-001 design.
- Produces: exact Amendment 1 proposal bytes and the constitutional rules that
  slices 2-10 implement fail-closed.

- [ ] **Step 1: Verify the committed immutable task base and add the failing source guard**

Execute and commit the recorded task-base contract above, then create the test
file with this exact code:

```rust
// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

const FROZEN_D9_BLAKE3: &str = "c1e89db47a30849d41e6db9c4c23d52d9dfbf3a820f2695dcdbcade6d42bd6af";
const AMENDMENT_1_BLAKE3: &str = "38330feabc0d18c5d00eb7268631c6d92dc608118f465fc84e07871bd7217c81";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_bytes(path: &str) -> Vec<u8> {
    fs::read(repository_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_text(path: &str) -> String {
    String::from_utf8(read_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
}

fn assert_contains_all(document: &str, required: &[&str]) {
    for value in required {
        assert!(
            document.contains(value),
            "missing required contract text: {value}"
        );
    }
}

#[test]
fn amendment_is_separate_from_frozen_d9_and_remains_nonbinding() {
    let frozen = read_bytes("governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md");
    assert_eq!(blake3::hash(&frozen).to_hex().as_str(), FROZEN_D9_BLAKE3);

    let amendment_path = "governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md";
    let amendment_bytes = read_bytes(amendment_path);
    assert_eq!(
        blake3::hash(&amendment_bytes).to_hex().as_str(),
        AMENDMENT_1_BLAKE3
    );
    let amendment = String::from_utf8(amendment_bytes).expect("D9 Amendment 1 must be UTF-8");
    assert_contains_all(
        &amendment,
        &[
            "# D9-COUNCIL-CHARTER-AMENDMENT-1",
            "**Status:** PROPOSED - not ratified, not enacted.",
            FROZEN_D9_BLAKE3,
            "OpenAI, Anthropic, xAI, and Alphabet/Google Gemini",
            "all five eligible Council seats",
            "all five eligible AI-IRB seats",
            "Chair approval cannot manufacture Council or AI-IRB unanimity",
            "max_iterations",
            "human-attested AAR and RCA",
            "DF-ROADMAP-001",
        ],
    );
    assert!(!amendment.contains("**Status:** RATIFIED"));
    assert!(!amendment.contains("**Status:** ENACTED"));
}
```

- [ ] **Step 2: Run the guard and capture RED**

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract amendment_is_separate_from_frozen_d9_and_remains_nonbinding -- --exact --nocapture
```

Expected: `FAIL` with `failed to read governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md` because the amendment does not exist. A passing test is invalid RED evidence.

- [ ] **Step 3: Create the exact amendment proposal**

Create `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md` with the
standard Apache-2.0 comment header used by D9 followed by this exact body:

```markdown
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

# D9-COUNCIL-CHARTER-AMENDMENT-1

**Status:** PROPOSED - not ratified, not enacted.
**Protocol:** DF-PROTOCOL-001.
**Proposed:** 2026-07-16.
**Human Co-PI and Chair:** Bob Stewart.
**AI Co-PI:** Codex, as an authorship role requiring a separately issued DID,
provider/model/session attestation, and signature before it can occupy a seat.
**Predecessor:** `governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md`, exact-byte
BLAKE3 `c1e89db47a30849d41e6db9c4c23d52d9dfbf3a820f2695dcdbcade6d42bd6af`.

This proposal amends D9 without editing or superseding its frozen bytes.
Content addressing is not enactment. Nothing in this proposal is binding until
the exact amendment bytes are authenticated and ratified through the existing
constitutional process. Before that receipt exists, Council and AI-IRB
outcomes are advisory and every runtime request for binding mode must fail
closed.

## 1. Authority object

The only ordinary binding instrument inside a ratified protocol envelope is
the signed, versioned, content-addressed `PeerReviewedProtocolPackageV1`.
Dashboard state, detached votes, prose reports, model judgments, mutable
projections, and adjacent-product status cannot authorize action. Every
executed action names the exact protocol version, canonical package hash,
tenant, phase, and envelope. Material change creates a new package version and
review cycle.

Constitutional changes, entrenched-invariant changes, provider/evidence-floor
changes, and envelope expansion use the extraordinary human-governed path.
No Council, AI-IRB, Chair, administrator, Co-PI, or product UI may expand its
own authority through ordinary protocol action.

## 2. Roles and separation

- Co-PIs author the protocol, answer review, maintain evidence, and propose
  amendments. A Co-PI cannot occupy an independent review seat for that work.
- AI-PI Council performs separately assigned governance, legal, architecture,
  security, and operations review roles.
- AI-IRB performs initial and continuing risk/benefit, monitoring, adverse and
  progressive event, AI-SDLC, corrective-action, and reset review under DIDs,
  keys, assignments, context manifests, and attestations separate from Council.
- The independent evidence member supplies a non-provider evidence class and
  proves independence from all four providers and both Co-PIs.
- The Chair is ex officio and outside both five-seat eligible sets. The Chair
  may observe, comment, request evidence, vote, challenge, escalate, and sign a
  reset. The Chair cannot enlarge an envelope or replace a missing AI vote.

Every role is bound to an authenticated DID, signer kind, tenant, consent,
bailment licensure, authority chain, conflict state, provenance, public key,
validity interval, and signed context. Request bodies cannot self-declare these
facts as authority.

## 3. Eligible seats and attestation

The Council eligible set contains provider seats for OpenAI, Anthropic, xAI,
and Alphabet/Google Gemini plus one independent non-provider seat. The AI-IRB
has the same five-class composition under separate DIDs, keys, context
manifests, assignments, and attestations. The Chair is not a sixth Council or
AI-IRB seat.

Each active seat attestation binds provider or independent controller, exact
model or human reviewer identifier, observable version, system-configuration
hash, sampling parameters, tool policy, context-manifest hash, behavioral
fingerprint, signing key, validity interval, Council-or-AI-IRB seat kind, and
conflict declaration. A changed model, configuration, controller, key,
fingerprint, validity interval, or assignment requires re-attestation before a
new vote can count.

## 4. Eligible unanimity and independence floors

Binding authorization requires Approve from all five eligible Council seats,
Approve from all five eligible AI-IRB seats, all four provider classes, and at
least two independent evidence classes including the non-provider class.
These are constitutional floors, not configurable targets.

Missing vote, abstention, rejection, unavailability, recusal, expiry,
attestation change, coordination finding, conflict, or invalid signature does
not remove a seat from the ratified denominator. When a recusal or unavailable
seat prevents the floor, the outcome is nonbinding until a content-addressed
roster amendment or valid replacement attestation is ratified. Provider prose
cannot satisfy the independent non-provider evidence class. No author, Co-PI,
or common controller can review itself through another label or session.

## 5. Dissent and Chair intervention

Authorization dissent prevents new eligible unanimity and therefore prevents
authorization. Monitoring dissent on an already authorized protocol creates a
mandatory Chair alert and continuing-review item but does not manufacture a
protocol-wide stop. Every dissent remains immutable and visible in the package.

Chair dispositions are `Approve`, `Abstain`, `Comment`, and `Reject`. The
signed disposition and effect are fixed before submission. Chair approval
cannot manufacture Council or AI-IRB unanimity. `Reject` is a scoped
HumanOverride challenge and immediately holds the named action, protocol, or
envelope scope. `Abstain` and `Comment` preserve participation without changing
eligible unanimity.

## 6. Ratified protocol envelope

Ordinary authority is limited by exact protocol ID and version, package hash,
constitutional hash, domain, purpose, permitted actions and systems, tenant,
datasets, actor classes, resource ceilings, risk ceiling, start/end HLC
bounds, and a pre-ratified phase ladder. Every requested action must be a
subset of each dimension. Any increase or unmatched dimension returns to the
extraordinary human-governed path.

Consent, bailment licensure, tenant isolation, provenance, human override,
kernel adjudication, signature verification, and usage accounting cannot be
waived by a protocol envelope.

## 7. Continuing review and event taxonomy

Every active protocol receives event-driven review for governed actions,
claim breaches, incidents, dissents, dependency/model changes, evidence
revocation, progressive events, adverse events, unanticipated problems, and
AI-SDLC transgressions. Bounded scheduled review, a daily Chair digest, and a
monthly recovery exercise use authenticated schedule identifiers and
caller-supplied HLC timestamps.

An autonomous evaluation declares `loop.max_iterations` as a positive integer
no greater than 25, an explicit success stop condition, a repeat-failure stop
after the same validation failure occurs twice, and an escalation destination.
No workflow output can authorize another iteration, code change, merge,
credential access, trust claim, or constitutional conclusion without fresh
repository and authority verification.

`ProgressiveEvent`, `AdverseEvent`, `UnanticipatedProblem`, and
`AiSdlcTransgression` preserve severity, expectedness, relatedness, affected
claims, source evidence, reporter, HLC timestamp, immediate containment,
disposition, and receipt root. Automated classifiers may route but never
discard an event. Each mandatory notification destination receives an
independent delivery attempt and receipt.

## 8. Stop, CAPA, RESET, and promotion

A kernel denial stops its individual action. A Chair challenge places an
immediate scoped hold. Protocol-wide AI-IRB E-STOP requires the mathematical
ceiling of two-thirds of active provider classes and at least two independent
evidence classes including a non-provider class; four active provider classes
therefore require three provider classes. The receipt records eligible set,
numerator, denominator, evidence classes, scope, and threshold.

E-STOP denies new governed actions in scope, preserves emergency human access
and evidence capture, emits parallel mandatory notifications, and opens AAR,
RCA, and CAPA records. It cannot be cleared by deletion, edit,
acknowledgement, idempotent replay, sibling API, or projection change.

RESET applies only to the stopped protocol and scope. It requires a
Chair-designated human investigator's human-attested AAR and RCA, completed
CAPA, deterministic recurrence evidence, all five eligible Council approvals,
all five eligible AI-IRB approvals, and the Chair's signature. RESET creates a
new reviewed protocol version and never erases the event or reuses the stopped
package hash.

A progressive event may promote only to the next recorded phase. Promotion
requires eligible unanimity from Council and AI-IRB plus immediate Chair
notice. Any change outside the phase ladder or envelope is constitutional or
envelope expansion and cannot use this path.

## 9. Persistence and publication authority

Production Decision Forum projections live in tenant-scoped tables in the
`dagdb` schema. Immutable governance events append to `dagdb_receipts` and
reconstruct through `dagdb_subject_receipt_heads`. Every governed mutation and
receipt append commits atomically in one transaction. Missing or degraded DAG
DB, failed migration, failed RLS tenant binding, stale receipt head, replay
conflict, broken link, tenant mismatch, receipt failure, or projection failure
must fail closed without an in-memory or `public`-schema authority fallback.

Canonical CBOR with a versioned domain-separated BLAKE3 hash is authoritative.
JSON is transport only. Markdown, accessible HTML, PDF/A, and manifests are
hermetic deterministic projections. A projection with a mismatched digest
cannot be published as the authoritative copy.

## 10. Adjacent products and commercial boundary

Generic EXOCHAIN and `crates/decision-forum` primitives remain Apache-2.0.
Decision Forum product UI and operating assets, CrossChecked, CyberMedica,
LegalDyne, and LiveSafe require commercial terms, bailment licensure, isolated
credentials, and `exo-economy-use-event-v1` accounting. They gain neither
Apache rights nor constitutional enforcement by proximity.

CrossChecked may perform licensed blind assignment, commitment custody,
signed reveal, and public evidence presentation. It cannot vote, authorize,
originate EXOCHAIN receipts, decide conflicts, store core signing keys, or
weaken core when absent. Invalid, absent, unlicensed, or unavailable blind
custody fails closed when blinding is required.

## 11. Genesis and research boundary

After the minimum publication path is operational, the Co-PIs may submit exact
Git commit hashes for pre-activation design, plans, reviews, implementation,
and tests. A prospective `GenesisAdoptionReceipt` records chronology, performs
ordinary review of unchanged historical artifacts, and authorizes only
subsequent execution. It cannot fabricate retroactive signatures or rewrite
pre-activation acts as natively receipted.

DAG DB retrieval quality, compression, ranking, model-judged answer quality,
token savings, and economic-thesis work are excluded from DF-PROTOCOL-001
implementation. Those hypotheses are recorded only in `DF-ROADMAP-001` for a
separate Decision Forum prioritization and authorization decision.

## 12. Enactment conditions

Binding mode remains unavailable until all of the following exist and verify:

1. exact Amendment 1 content hash and immutable predecessor link;
2. authenticated constitutional ratification receipt for those exact bytes;
3. active Co-PI, Chair, Council, AI-IRB, and independent-seat credentials;
4. implemented and independently validated package, authority, persistence,
   publication, stop/reset, and bypass-closure acceptance evidence;
5. tenant-scoped consent, licensure, authority, and usage-accounting policy;
6. genesis adoption of pre-activation evidence without retroactive claims; and
7. a kernel configuration that recognizes the ratified hash without mutating
   the immutable kernel after initialization.

Until every condition verifies, the implementation may store and publish
advisory evidence but must reject binding authorization.
```

- [ ] **Step 4: Run GREEN and verify the predecessor hash directly**

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract amendment_is_separate_from_frozen_d9_and_remains_nonbinding -- --exact --nocapture
b3sum governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md
TASK_BASE="$(tr -d '\n' < .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha)"
git cat-file -e "$TASK_BASE^{commit}"
git diff "$TASK_BASE" -- governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md governance/proposals/SEAT-000-COORDINATOR-RECORD.md
```

Expected: test `PASS`; `b3sum` prints the frozen digest; the targeted `git diff`
is empty.

- [ ] **Step 5: Commit the amendment and its guard**

```bash
git add crates/decision-forum/tests/df_protocol_001_normative_contract.rs governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md
git commit -m "docs(governance): propose D9 peer-review amendment"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

### Task 2: Add the reviewed package transport schema

**Files:**

- Modify: `crates/decision-forum/tests/df_protocol_001_normative_contract.rs`
- Modify: `crates/decision-forum/Cargo.toml`
- Modify: `Cargo.lock`
- Create: `governance/schemas/peer-reviewed-protocol-package-v1.schema.json`

**Interfaces:**

- Consumes: Amendment 1 role, envelope, persistence, and publication rules.
- Produces: exact `PeerReviewedProtocolPackageV1` JSON transport field names
  and primitive representations for slices 2, 4, 5, and 6.

- [ ] **Step 1: Pin the existing validator and add the failing schema contract test**

Create the missing schema directory before the RED run:

```bash
mkdir -p governance/schemas
```

Add this exact dev dependency under `[dev-dependencies]` in
`crates/decision-forum/Cargo.toml`:

```toml
ed25519-dalek = { workspace = true }
jsonschema = { version = "=0.19.1", default-features = false }
```

Run `cargo metadata --no-deps --format-version 1 >/dev/null` once to update the
Decision Forum dependency list in `Cargo.lock`, then run
`cargo metadata --locked --no-deps --format-version 1 >/dev/null` to prove the
lock is current. Both packages already exist in the workspace lock; the
validator remains exact at 0.19.1 and Ed25519 remains workspace-pinned at
2.2.0. These test-only dependencies provide executable schema and real
signature RED evidence, not production behavior or protocol credentials.

Append this exact test to
`crates/decision-forum/tests/df_protocol_001_normative_contract.rs`:

```rust
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use jsonschema::{Draft, JSONSchema};
use serde_json::{Value, json};

fn repeated_hex(character: char, length: usize) -> String {
    std::iter::repeat_n(character, length).collect()
}

fn hash256() -> String {
    repeated_hex('a', 64)
}

fn hash_with(character: char) -> String {
    repeated_hex(character, 64)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("expected {} lowercase hex characters", N * 2));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
        bytes[index] = u8::from_str_radix(pair, 16).map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}

fn fixture_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn fixture_key_material(seed: u8) -> (String, String) {
    let verification_key = encode_hex(&fixture_signing_key(seed).verifying_key().to_bytes());
    let signing_key_id = hash_fixture(
        "exo.decision_forum.verification_key_id.v1",
        &json!({ "verification_key": verification_key }),
    );
    (signing_key_id, verification_key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedAuthorityBindingV1 {
    tenant_id: String,
    protocol_id: String,
    actor_did: String,
    scope: String,
    signing_key_id: String,
    verification_key: String,
    authority_chain_hash: String,
}

#[derive(Clone, Debug)]
struct VerifiedAuthorityRegistryV1 {
    entries: BTreeMap<(String, String), VerifiedAuthorityBindingV1>,
}

impl VerifiedAuthorityRegistryV1 {
    fn resolve(
        &self,
        tenant_id: &str,
        protocol_id: &str,
        actor_did: &str,
        scope: &str,
    ) -> Result<&VerifiedAuthorityBindingV1, String> {
        let authority = self
            .entries
            .get(&(actor_did.to_owned(), scope.to_owned()))
            .ok_or_else(|| format!("unverified authority {actor_did} for scope {scope}"))?;
        if authority.tenant_id != tenant_id
            || authority.protocol_id != protocol_id
            || authority.actor_did != actor_did
            || authority.scope != scope
        {
            return Err("verified authority tenant/protocol/scope binding mismatch".to_owned());
        }
        Ok(authority)
    }
}

fn fixture_authority_registry() -> VerifiedAuthorityRegistryV1 {
    let mut entries = BTreeMap::new();
    for (actor_did, scope, seed, chain_character) in [
        ("did:exo:bob-stewart", "ChairInterventionV1", 12_u8, '5'),
        (
            "did:exo:bob-stewart",
            "PublicationAuthorizationReceiptV1",
            11_u8,
            '6',
        ),
        (
            "did:exo:executor-13",
            "ProtocolExecutionReceiptV1",
            13_u8,
            '7',
        ),
        (
            "did:exo:executor-14",
            "ProtocolExecutionReceiptV1",
            14_u8,
            '8',
        ),
    ] {
        let (signing_key_id, verification_key) = fixture_key_material(seed);
        let binding = VerifiedAuthorityBindingV1 {
            tenant_id: "tenant-1".to_owned(),
            protocol_id: "DF-PROTOCOL-001".to_owned(),
            actor_did: actor_did.to_owned(),
            scope: scope.to_owned(),
            signing_key_id,
            verification_key,
            authority_chain_hash: hash_with(chain_character),
        };
        entries.insert((actor_did.to_owned(), scope.to_owned()), binding);
    }
    VerifiedAuthorityRegistryV1 { entries }
}

fn authority_reference(authority: &VerifiedAuthorityBindingV1) -> Value {
    json!({
        "binding_kind": "NonSeatAuthority",
        "tenant_id": authority.tenant_id,
        "protocol_id": authority.protocol_id,
        "actor_did": authority.actor_did,
        "controller_did": authority.actor_did,
        "scope": authority.scope,
        "signing_key_id": authority.signing_key_id,
        "verification_key": authority.verification_key,
        "authority_chain_hash": authority.authority_chain_hash
    })
}

fn fixture_authority_seed(actor_did: &str, scope: &str) -> u8 {
    match (actor_did, scope) {
        ("did:exo:bob-stewart", "ChairInterventionV1") => 12,
        ("did:exo:bob-stewart", "PublicationAuthorizationReceiptV1") => 11,
        ("did:exo:executor-13", "ProtocolExecutionReceiptV1") => 13,
        ("did:exo:executor-14", "ProtocolExecutionReceiptV1") => 14,
        ("did:exo:attacker", "ProtocolExecutionReceiptV1") => 15,
        _ => panic!("unexpected fixture authority {actor_did} for {scope}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedSeatAuthorityBindingV1 {
    tenant_id: String,
    protocol_id: String,
    seat_did: String,
    seat_kind: String,
    provider_class: String,
    controller_did: String,
    seat_signing_key_id: String,
    seat_verification_key: String,
    controller_signing_key_id: String,
    controller_verification_key: String,
    context_manifest_hash: String,
    seat_attestation_hash: String,
    valid_from: Value,
    valid_until: Value,
    independent_control_proof_hash: Option<String>,
    authority_scope: String,
    verified_authority_chain_hash: String,
}

#[derive(Clone, Debug)]
struct VerifiedSeatAuthorityRegistryV1 {
    entries: BTreeMap<(String, String), VerifiedSeatAuthorityBindingV1>,
}

impl VerifiedSeatAuthorityRegistryV1 {
    fn resolve(
        &self,
        tenant_id: &str,
        protocol_id: &str,
        seat_did: &str,
        seat_kind: &str,
    ) -> Result<&VerifiedSeatAuthorityBindingV1, String> {
        let binding = self
            .entries
            .get(&(seat_did.to_owned(), seat_kind.to_owned()))
            .ok_or_else(|| {
                format!("seat {seat_did} has no verified {seat_kind} authority binding")
            })?;
        if binding.tenant_id != tenant_id
            || binding.protocol_id != protocol_id
            || binding.seat_did != seat_did
            || binding.seat_kind != seat_kind
        {
            return Err("verified seat authority tenant/protocol/body mismatch".to_owned());
        }
        Ok(binding)
    }
}

type FixtureSeatRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u8,
    u8,
    char,
    Option<char>,
);

fn fixture_seat_rows() -> [FixtureSeatRow; 10] {
    [
        (
            "did:exo:openai",
            "Council",
            "OpenAI",
            "did:exo:controller-openai-council",
            "CouncilSeatV1",
            1,
            21,
            '1',
            None,
        ),
        (
            "did:exo:anthropic",
            "Council",
            "Anthropic",
            "did:exo:controller-anthropic-council",
            "CouncilSeatV1",
            2,
            22,
            '2',
            None,
        ),
        (
            "did:exo:xai",
            "Council",
            "xAI",
            "did:exo:controller-xai-council",
            "CouncilSeatV1",
            3,
            23,
            '3',
            None,
        ),
        (
            "did:exo:gemini",
            "Council",
            "AlphabetGoogleGemini",
            "did:exo:controller-google-council",
            "CouncilSeatV1",
            4,
            24,
            '4',
            None,
        ),
        (
            "did:exo:independent",
            "Council",
            "IndependentNonProvider",
            "did:exo:controller-independent-council",
            "CouncilSeatV1",
            5,
            25,
            '5',
            Some('a'),
        ),
        (
            "did:exo:irb-openai",
            "AiIrb",
            "OpenAI",
            "did:exo:controller-openai-irb",
            "AiIrbSeatV1",
            6,
            26,
            '6',
            None,
        ),
        (
            "did:exo:irb-anthropic",
            "AiIrb",
            "Anthropic",
            "did:exo:controller-anthropic-irb",
            "AiIrbSeatV1",
            7,
            27,
            '7',
            None,
        ),
        (
            "did:exo:irb-xai",
            "AiIrb",
            "xAI",
            "did:exo:controller-xai-irb",
            "AiIrbSeatV1",
            8,
            28,
            '8',
            None,
        ),
        (
            "did:exo:irb-gemini",
            "AiIrb",
            "AlphabetGoogleGemini",
            "did:exo:controller-google-irb",
            "AiIrbSeatV1",
            9,
            29,
            '9',
            None,
        ),
        (
            "did:exo:irb-independent",
            "AiIrb",
            "IndependentNonProvider",
            "did:exo:controller-independent-irb",
            "AiIrbSeatV1",
            10,
            30,
            'b',
            Some('b'),
        ),
    ]
}

fn fixture_controller_seed(seat_did: &str) -> u8 {
    fixture_seat_rows()
        .into_iter()
        .find(|row| row.0 == seat_did)
        .map(|row| row.6)
        .unwrap_or_else(|| panic!("unexpected fixture seat controller {seat_did}"))
}

fn unsigned_signature_envelope(target: &str, seed: u8) -> Value {
    let (signing_key_id, verification_key) = fixture_key_material(seed);
    json!({
        "algorithm": "Ed25519",
        "signing_key_id": signing_key_id,
        "verification_key": verification_key,
        "signature": repeated_hex('0', 128),
        "signed_payload_hash": repeated_hex('0', 64),
        "signed_payload_target": target
    })
}

fn sign_payload(domain: &str, target: &str, body: &Value, seed: u8) -> Value {
    let digest = exo_core::hash::hash_structured(&(domain, body))
        .expect("fixture signing payload must encode as canonical CBOR");
    let signing_key = fixture_signing_key(seed);
    let signature = signing_key.sign(digest.as_bytes());
    let (signing_key_id, verification_key) = fixture_key_material(seed);
    json!({
        "algorithm": "Ed25519",
        "signing_key_id": signing_key_id,
        "verification_key": verification_key,
        "signature": encode_hex(&signature.to_bytes()),
        "signed_payload_hash": digest.to_string(),
        "signed_payload_target": target
    })
}

fn verify_signed_payload(
    domain: &str,
    target: &str,
    body: &Value,
    envelope: &Value,
    expected_signing_key_id: &str,
    expected_verification_key: &str,
) -> Result<(), String> {
    if envelope["algorithm"] != "Ed25519"
        || envelope["signed_payload_target"] != target
        || envelope["signing_key_id"] != expected_signing_key_id
        || envelope["verification_key"] != expected_verification_key
    {
        return Err(format!("{target} signature authority mismatch"));
    }
    let digest = exo_core::hash::hash_structured(&(domain, body))
        .map_err(|error| format!("{target} payload hashing failed: {error}"))?;
    if envelope["signed_payload_hash"] != digest.to_string() {
        return Err(format!("{target} signed payload hash mismatch"));
    }
    let verification_key_bytes = decode_hex::<32>(expected_verification_key)?;
    let verification_key = VerifyingKey::from_bytes(&verification_key_bytes)
        .map_err(|error| format!("{target} verification key is invalid: {error}"))?;
    let signature_bytes = decode_hex::<64>(
        envelope["signature"]
            .as_str()
            .ok_or_else(|| format!("{target} signature missing"))?,
    )?;
    let signature = DalekSignature::from_bytes(&signature_bytes);
    verification_key
        .verify(digest.as_bytes(), &signature)
        .map_err(|error| format!("{target} Ed25519 verification failed: {error}"))
}

fn timestamp(physical_ms: u64) -> Value {
    json!({ "physical_ms": physical_ms, "logical": 0 })
}

fn seat_attestation_signing_payload_fixture(attestation: &Value) -> Value {
    let mut payload = attestation.clone();
    payload
        .as_object_mut()
        .expect("fixture seat attestation must be an object")
        .remove("signature");
    payload
}

fn seat_attestation_from_binding(
    binding: &VerifiedSeatAuthorityBindingV1,
    controller_seed: u8,
) -> Value {
    let evidence_class = if binding.provider_class == "IndependentNonProvider" {
        "IndependentNonProviderEvidence"
    } else {
        "ProviderModelJudgment"
    };
    let mut attestation = json!({
        "tenant_id": binding.tenant_id,
        "protocol_id": binding.protocol_id,
        "seat_id": binding.seat_did,
        "seat_kind": binding.seat_kind,
        "provider_class": binding.provider_class,
        "controller_did": binding.controller_did,
        "independent_control_proof_hash": binding.independent_control_proof_hash,
        "reviewer_identifier": "reviewer-v1",
        "observable_version": "model-v1",
        "system_configuration_hash": hash256(),
        "sampling_parameters_hash": hash256(),
        "tool_policy_hash": hash256(),
        "context_manifest_hash": binding.context_manifest_hash,
        "behavioral_fingerprint_hash": hash256(),
        "signing_key_id": binding.seat_signing_key_id,
        "verification_key": binding.seat_verification_key,
        "valid_from": binding.valid_from,
        "valid_until": binding.valid_until,
        "evidence_classes": [evidence_class],
        "conflict_declaration_hash": hash256(),
        "authority_scope": binding.authority_scope,
        "authority_chain_hash": binding.verified_authority_chain_hash,
        "signature": unsigned_signature_envelope("SeatAttestationV1", controller_seed)
    });
    attestation["signature"] = sign_payload(
        "exo.decision_forum.seat_attestation_signing_payload.v1",
        "SeatAttestationV1",
        &seat_attestation_signing_payload_fixture(&attestation),
        controller_seed,
    );
    attestation
}

fn fixture_seat_authority_registry() -> VerifiedSeatAuthorityRegistryV1 {
    let mut entries = BTreeMap::new();
    for (
        seat_did,
        seat_kind,
        provider_class,
        controller_did,
        authority_scope,
        seat_seed,
        controller_seed,
        context_character,
        proof_character,
    ) in fixture_seat_rows()
    {
        let (seat_signing_key_id, seat_verification_key) = fixture_key_material(seat_seed);
        let (controller_signing_key_id, controller_verification_key) =
            fixture_key_material(controller_seed);
        let mut binding = VerifiedSeatAuthorityBindingV1 {
            tenant_id: "tenant-1".to_owned(),
            protocol_id: "DF-PROTOCOL-001".to_owned(),
            seat_did: seat_did.to_owned(),
            seat_kind: seat_kind.to_owned(),
            provider_class: provider_class.to_owned(),
            controller_did: controller_did.to_owned(),
            seat_signing_key_id,
            seat_verification_key,
            controller_signing_key_id,
            controller_verification_key,
            context_manifest_hash: hash_with(context_character),
            seat_attestation_hash: repeated_hex('0', 64),
            valid_from: timestamp(0),
            valid_until: timestamp(2),
            independent_control_proof_hash: proof_character.map(hash_with),
            authority_scope: authority_scope.to_owned(),
            verified_authority_chain_hash: hash_fixture(
                "exo.decision_forum.verified_seat_authority_chain.v1",
                &json!({
                    "tenant_id": "tenant-1",
                    "protocol_id": "DF-PROTOCOL-001",
                    "seat_did": seat_did,
                    "seat_kind": seat_kind,
                    "controller_did": controller_did,
                    "authority_scope": authority_scope
                }),
            ),
        };
        let attestation = seat_attestation_from_binding(&binding, controller_seed);
        binding.seat_attestation_hash =
            hash_fixture("exo.decision_forum.seat_attestation.v1", &attestation);
        entries.insert((seat_did.to_owned(), seat_kind.to_owned()), binding);
    }
    VerifiedSeatAuthorityRegistryV1 { entries }
}

fn seat_authority_reference(binding: &VerifiedSeatAuthorityBindingV1) -> Value {
    json!({
        "binding_kind": "SeatAuthority",
        "tenant_id": binding.tenant_id,
        "protocol_id": binding.protocol_id,
        "actor_did": binding.seat_did,
        "controller_did": binding.controller_did,
        "scope": binding.authority_scope,
        "signing_key_id": binding.seat_signing_key_id,
        "verification_key": binding.seat_verification_key,
        "authority_chain_hash": binding.verified_authority_chain_hash
    })
}

fn hlc_tuple(timestamp: &Value) -> Result<(u64, u64), String> {
    Ok((
        timestamp["physical_ms"]
            .as_u64()
            .ok_or_else(|| "HLC physical_ms missing".to_owned())?,
        timestamp["logical"]
            .as_u64()
            .ok_or_else(|| "HLC logical missing".to_owned())?,
    ))
}

fn verify_seat_attestation(
    attestation: &Value,
    binding: &VerifiedSeatAuthorityBindingV1,
    verification_at: &Value,
) -> Result<(), String> {
    let expected =
        seat_attestation_from_binding(binding, fixture_controller_seed(&binding.seat_did));
    if attestation != &expected
        || hash_fixture("exo.decision_forum.seat_attestation.v1", attestation)
            != binding.seat_attestation_hash
    {
        return Err(
            "package seat attestation differs from verified seat authority binding".to_owned(),
        );
    }
    if hlc_tuple(verification_at)? < hlc_tuple(&binding.valid_from)?
        || hlc_tuple(verification_at)? > hlc_tuple(&binding.valid_until)?
    {
        return Err("verified seat authority is outside its HLC validity interval".to_owned());
    }
    verify_signed_payload(
        "exo.decision_forum.seat_attestation_signing_payload.v1",
        "SeatAttestationV1",
        &seat_attestation_signing_payload_fixture(attestation),
        &attestation["signature"],
        &binding.controller_signing_key_id,
        &binding.controller_verification_key,
    )
}

fn fixture_seed_for_seat(seat_id: &str) -> u8 {
    match seat_id {
        "did:exo:openai" => 1,
        "did:exo:anthropic" => 2,
        "did:exo:xai" => 3,
        "did:exo:gemini" => 4,
        "did:exo:independent" => 5,
        "did:exo:irb-openai" => 6,
        "did:exo:irb-anthropic" => 7,
        "did:exo:irb-xai" => 8,
        "did:exo:irb-gemini" => 9,
        "did:exo:irb-independent" => 10,
        _ => panic!("unexpected fixture seat {seat_id}"),
    }
}

fn seat_attestation(
    seat_id: &str,
    seat_kind: &str,
    provider_class: &str,
    _evidence_class: &str,
) -> Value {
    let registry = fixture_seat_authority_registry();
    let binding = registry
        .resolve("tenant-1", "DF-PROTOCOL-001", seat_id, seat_kind)
        .expect("fixture seat has independently verified authority");
    assert_eq!(binding.provider_class, provider_class);
    seat_attestation_from_binding(binding, fixture_controller_seed(seat_id))
}

fn assignment(seat_id: &str, seat_kind: &str, ordinal: u8) -> Value {
    let review_role = match ordinal {
        10 => "Governance",
        11 => "Legal",
        12 => "Architecture",
        13 => "Security",
        14 => "Operations",
        20 => "RiskBenefit",
        21 => "Monitoring",
        22 => "AdverseEvent",
        23 => "ProgressiveEvent",
        24 => "CorrectiveAction",
        _ => panic!("unexpected fixture assignment ordinal {ordinal}"),
    };
    json!({
        "assignment_id": format!("00000000-0000-4000-8000-{ordinal:012}"),
        "seat_id": seat_id,
        "seat_kind": seat_kind,
        "protocol_version_hash": hash256(),
        "seat_attestation_hash": hash256(),
        "context_manifest_hash": match seat_id {
            "did:exo:openai" => hash_with('1'),
            "did:exo:anthropic" => hash_with('2'),
            "did:exo:xai" => hash_with('3'),
            "did:exo:gemini" => hash_with('4'),
            "did:exo:independent" => hash_with('5'),
            "did:exo:irb-openai" => hash_with('6'),
            "did:exo:irb-anthropic" => hash_with('7'),
            "did:exo:irb-xai" => hash_with('8'),
            "did:exo:irb-gemini" => hash_with('9'),
            "did:exo:irb-independent" => hash_with('b'),
            _ => panic!("unexpected fixture seat {seat_id}"),
        },
        "review_role": review_role,
        "blind_commitment": hash256(),
        "conflict_declaration_hash": hash256(),
        "assigned_at": timestamp(0)
    })
}

fn quorum_proof(seat_kind: &str, ordinal: u8) -> Value {
    json!({
        "proof_id": format!("00000000-0000-4000-8000-{ordinal:012}"),
        "seat_kind": seat_kind,
        "eligible_seat_hashes": [hash_with('1'), hash_with('2'), hash_with('3'), hash_with('4'), hash_with('5')],
        "approve_seat_hashes": [hash_with('1'), hash_with('2'), hash_with('3'), hash_with('4'), hash_with('5')],
        "provider_classes": ["OpenAI", "Anthropic", "xAI", "AlphabetGoogleGemini"],
        "evidence_classes": ["DeterministicTest", "IndependentNonProviderEvidence"],
        "eligible_count": 5,
        "approve_count": 5,
        "required_count": 5,
        "result": "EligibleUnanimity",
        "computed_at": timestamp(1),
        "proof_hash": hash256()
    })
}

fn disposition(seat_kind: &str, seat_id: &str, target: &str, seed: u8) -> Value {
    json!({
        "disposition_id": format!("00000000-0000-4000-8000-{seed:012}"),
        "seat_id": seat_id,
        "seat_kind": seat_kind,
        "choice": "Approve",
        "authorization_target_hash": hash_with('e'),
        "protocol_version_hash": hash256(),
        "review_bundle_hash": hash256(),
        "eligible_set_hash": hash256(),
        "seat_attestation_hash": hash256(),
        "context_manifest_hash": hash256(),
        "signed_at": timestamp(1),
        "signature": unsigned_signature_envelope(target, seed)
    })
}

fn five_seat_roster(seat_kind: &str) -> Value {
    let prefix = if seat_kind == "Council" { "" } else { "irb-" };
    json!({
        "openai": seat_attestation(
            &format!("did:exo:{prefix}openai"), seat_kind, "OpenAI", "ProviderModelJudgment"
        ),
        "anthropic": seat_attestation(
            &format!("did:exo:{prefix}anthropic"), seat_kind, "Anthropic", "ProviderModelJudgment"
        ),
        "xai": seat_attestation(
            &format!("did:exo:{prefix}xai"), seat_kind, "xAI", "ProviderModelJudgment"
        ),
        "alphabet_google_gemini": seat_attestation(
            &format!("did:exo:{prefix}gemini"), seat_kind, "AlphabetGoogleGemini", "ProviderModelJudgment"
        ),
        "independent_non_provider": seat_attestation(
            &format!("did:exo:{prefix}independent"), seat_kind, "IndependentNonProvider", "IndependentNonProviderEvidence"
        )
    })
}

fn peer_review(index: usize) -> Value {
    let assignment_ordinal = if index < 5 { index + 10 } else { index + 15 };
    let seed = (index + 1) as u8;
    json!({
        "review_id": format!("00000000-0000-4000-8001-{seed:012}"),
        "assignment_id": format!("00000000-0000-4000-8000-{assignment_ordinal:012}"),
        "protocol_version_hash": hash256(),
        "criteria_results_hash": hash_with(char::from_digit(seed.into(), 16).expect("fixture seed is hexadecimal")),
        "review_body_hash": hash_with(char::from_digit((seed + 1).into(), 16).expect("fixture seed is hexadecimal")),
        "disposition": "Approve",
        "sealed_at": timestamp(0),
        "authorization_target_hash": repeated_hex('0', 64),
        "signature": unsigned_signature_envelope("PeerReviewV1", seed)
    })
}

fn linked_review_hash(domain: &str, index: usize) -> String {
    hash_fixture(domain, &json!({ "review_index": index }))
}

fn linked_review_reference(kind: &str, domain: &str, index: usize) -> Value {
    json!({
        "kind": kind,
        "content_hash": linked_review_hash(domain, index),
        "media_type": "application/cbor"
    })
}

fn review_resolution(index: usize) -> Value {
    let review = peer_review(index);
    let ordinal = index + 1;
    json!({
        "resolution_id": format!("00000000-0000-4000-8003-{ordinal:012}"),
        "review_id": review["review_id"],
        "comment_hash": review["review_body_hash"],
        "author_response_hash": linked_review_hash(
            "exo.decision_forum.author_response.v1",
            index,
        ),
        "revision_diff_hash": linked_review_hash(
            "exo.decision_forum.revision_diff.v1",
            index,
        ),
        "resolution": "Accepted",
        "resolved_at": timestamp(0),
        "signature_hash": linked_review_hash(
            "exo.decision_forum.review_resolution_signature.v1",
            index,
        )
    })
}

fn genesis_evidence_bundle() -> Value {
    json!({
        "historical_commit_ids": [{
            "algorithm": "sha1",
            "digest": "23742d90ad4f08f62a668ca7b371b9e318177885"
        }],
        "chronology_manifest_hash": hash_with('2'),
        "historical_review_evidence_hash": hash_with('3')
    })
}

fn genesis_evidence_bundle_hash(bundle: &Value) -> String {
    hash_fixture("exo.decision_forum.genesis_evidence_bundle.v1", bundle)
}

fn genesis_adoption_receipt_root(receipt: &Value) -> String {
    let mut normalized = receipt.clone();
    normalized["receipt_root"] = json!(repeated_hex('0', 64));
    hash_fixture(
        "exo.decision_forum.genesis_adoption_receipt.v1",
        &normalized,
    )
}

fn genesis_adoption_receipt() -> Value {
    let evidence_bundle = genesis_evidence_bundle();
    let mut receipt = json!({
        "receipt_id": "00000000-0000-4000-8000-000000000007",
        "protocol_id": "DF-PROTOCOL-001",
        "pre_activation": true,
        "evidence_bundle_hash": genesis_evidence_bundle_hash(&evidence_bundle),
        "evidence_bundle": evidence_bundle,
        "prospective_effect_starts_at": timestamp(1),
        "retroactive_signature_claimed": false,
        "receipt_root": repeated_hex('0', 64)
    });
    receipt["receipt_root"] = json!(genesis_adoption_receipt_root(&receipt));
    receipt
}

fn valid_package() -> Value {
    let authority_registry = fixture_authority_registry();
    let chair_authority = authority_registry
        .resolve(
            "tenant-1",
            "DF-PROTOCOL-001",
            "did:exo:bob-stewart",
            "ChairInterventionV1",
        )
        .expect("fixture Chair authority is independently verified")
        .clone();
    let publisher_authority = authority_registry
        .resolve(
            "tenant-1",
            "DF-PROTOCOL-001",
            "did:exo:bob-stewart",
            "PublicationAuthorizationReceiptV1",
        )
        .expect("fixture publisher authority is independently verified")
        .clone();
    let council_ids = [
        "did:exo:openai",
        "did:exo:anthropic",
        "did:exo:xai",
        "did:exo:gemini",
        "did:exo:independent",
    ];
    let ai_irb_ids = [
        "did:exo:irb-openai",
        "did:exo:irb-anthropic",
        "did:exo:irb-xai",
        "did:exo:irb-gemini",
        "did:exo:irb-independent",
    ];
    let seat_authority_registry = fixture_seat_authority_registry();
    let seat_authority_references: Vec<Value> = council_ids
        .iter()
        .map(|seat_id| (seat_id, "Council"))
        .chain(ai_irb_ids.iter().map(|seat_id| (seat_id, "AiIrb")))
        .map(|(seat_id, seat_kind)| {
            seat_authority_reference(
                seat_authority_registry
                    .resolve("tenant-1", "DF-PROTOCOL-001", seat_id, seat_kind)
                    .expect("fixture seat authority reference is independently verified"),
            )
        })
        .collect();
    let council_votes: Vec<Value> = council_ids
        .iter()
        .enumerate()
        .map(|(index, seat_id)| {
            disposition(
                "Council",
                seat_id,
                "CouncilDispositionV1",
                (index + 1) as u8,
            )
        })
        .collect();
    let ai_irb_votes: Vec<Value> = ai_irb_ids
        .iter()
        .enumerate()
        .map(|(index, seat_id)| {
            disposition("AiIrb", seat_id, "AiIrbDispositionV1", (index + 6) as u8)
        })
        .collect();
    let signed_reviews: Vec<Value> = (0..10).map(peer_review).collect();
    let predecessor_chain = fixture_verified_predecessor(&authority_registry)
        .expect("fixture predecessor chain is independently verified");
    let reference = json!({
        "kind": "source",
        "content_hash": hash256(),
        "media_type": "application/octet-stream"
    });

    let package = json!({
        "schema_version": 1,
        "protocol_identity": {
            "protocol_id": "DF-PROTOCOL-001",
            "tenant_id": "tenant-1",
            "constitutional_hash": hash256(),
            "version": 2,
            "prior_version_hash": predecessor_chain.protocol_version_hash,
            "lifecycle_state": "Approved",
            "co_pi_dids": ["did:exo:bob-stewart", "did:exo:codex-session"],
            "chair_did": "did:exo:bob-stewart",
            "chair_authority": {
                "chair_did": "did:exo:bob-stewart",
                "signing_key_id": chair_authority.signing_key_id,
                "verification_key": chair_authority.verification_key,
                "authority_chain_hash": chair_authority.authority_chain_hash
            },
            "domain": "governance"
        },
        "protocol_document": {
            "abstract_text": "abstract",
            "purpose": "purpose",
            "hypotheses": [],
            "scope": "scope",
            "architecture": "architecture",
            "methods": ["method"],
            "implementation_controls": ["control"],
            "risks": ["risk"],
            "benefits": [],
            "consent_bailment_basis": "basis",
            "data_handling": "handling",
            "threat_model": ["threat"],
            "monitoring": "monitoring",
            "stopping_rules": ["stop"],
            "evaluation_method": "deterministic",
            "implementation_test_plan": ["test"],
            "claims": [],
            "closeout_criteria": ["close"]
        },
        "protocol_envelope": {
            "permitted_actions": ["publish"],
            "systems": ["decision-forum"],
            "tenants": ["tenant-1"],
            "datasets": [],
            "actor_classes": ["Reviewer"],
            "resource_ceilings": {
                "action_count": 25,
                "compute_milliseconds": 1000,
                "memory_bytes": 1048576
            },
            "risk_ceiling_basis_points": 1000,
            "starts_at": timestamp(0),
            "ends_at": timestamp(1),
            "phase_ladder": ["initial"]
        },
        "evidence_manifest": {
            "items": [reference.clone()],
            "independent_evidence_classes": [
                "DeterministicTest",
                "IndependentNonProviderEvidence"
            ],
            "negative_or_inconclusive_results": []
        },
        "review_bundle": {
            "council_seat_attestations": five_seat_roster("Council"),
            "ai_irb_seat_attestations": five_seat_roster("AiIrb"),
            "assignments": council_ids.iter().enumerate()
                .map(|(index, seat_id)| assignment(seat_id, "Council", (index + 10) as u8))
                .chain(ai_irb_ids.iter().enumerate()
                    .map(|(index, seat_id)| assignment(seat_id, "AiIrb", (index + 20) as u8)))
                .collect::<Vec<_>>(),
            "blind_commitments": [hash256()],
            "conflict_declarations": [reference.clone()],
            "signed_reviews": signed_reviews,
            "author_responses": (0..10)
                .map(|index| linked_review_reference(
                    "author-response",
                    "exo.decision_forum.author_response.v1",
                    index,
                ))
                .collect::<Vec<_>>(),
            "revision_diffs": (0..10)
                .map(|index| linked_review_reference(
                    "revision-diff",
                    "exo.decision_forum.revision_diff.v1",
                    index,
                ))
                .collect::<Vec<_>>(),
            "resolution_matrix": (0..10).map(review_resolution).collect::<Vec<_>>(),
            "reveal_package_hash": null
        },
        "disposition_bundle": {
            "council_eligible_set": council_ids,
            "ai_irb_eligible_set": ai_irb_ids,
            "council_votes": council_votes,
            "ai_irb_votes": ai_irb_votes,
            "dissents": [],
            "quorum_proofs": [quorum_proof("Council", 30), quorum_proof("AiIrb", 31)],
            "chair_interventions": [{
                "intervention_id": "00000000-0000-4000-8000-000000000006",
                "chair_did": "did:exo:bob-stewart",
                "choice": "Approve",
                "scope_hash": hash256(),
                "effect": "EndorsementOnly",
                "comment_hash": hash256(),
                "authorization_target_hash": repeated_hex('0', 64),
                "protocol_version_hash": hash256(),
                "signed_at": timestamp(0),
                "signature": unsigned_signature_envelope("ChairInterventionV1", 12)
            }],
            "kernel_verdicts": [reference.clone()],
            "authority_chain": seat_authority_references
                .into_iter()
                .chain([
                    authority_reference(&chair_authority),
                    authority_reference(&publisher_authority)
                ])
                .collect::<Vec<_>>(),
            "binding_mode": "BindingInsideRatifiedEnvelope"
        },
        "monitoring_plan": {
            "max_iterations": 25,
            "success_stop_condition": "all checks pass",
            "repeat_failure_limit": 2,
            "escalation_destination": "did:exo:bob-stewart",
            "scheduled_interval_hlc_units": 1,
            "claim_thresholds": [],
            "adverse_event_definitions": ["adverse"],
            "progressive_event_definitions": ["progressive"],
            "reporting_destinations": ["chair"],
            "event_payload_type_domains": [
                "exo.decision_forum.protocol_event.v1",
                "exo.decision_forum.estop_authorization.v1",
                "exo.decision_forum.capa_record.v1",
                "exo.decision_forum.reset_authorization.v1"
            ]
        },
        "systemic_learning_manifest": {
            "records": [],
            "candidate_roadmap_scenarios": [],
            "authority_effect": "ContextOnlyNoEnactmentAuthority"
        },
        "commercial_boundary": {
            "core_license": "Apache-2.0",
            "product_license_model": "commercial",
            "bailment_licensure_hash": hash256(),
            "permitted_use_hash": hash256(),
            "metering_class": "governance",
            "usage_accounting_policy": "exo-economy-use-event-v1"
        },
        "receipt_manifest": {
            "preauthorization_lifecycle_receipts": [{
                "receipt_hash": hash_with('6'),
                "lifecycle_state": "Approved",
                "authorized_package_root": null
            }],
            "prior_execution_receipt_chain": prior_execution_chain_reference(&predecessor_chain),
            "commitment_scheme": {
                "authorization_target_domain": "exo.decision_forum.protocol_authorization_target.v1",
                "seat_attestation_signing_payload_domain": "exo.decision_forum.seat_attestation_signing_payload.v1",
                "peer_review_signing_payload_domain": "exo.decision_forum.peer_review_signing_payload.v1",
                "council_disposition_signing_payload_domain": "exo.decision_forum.council_disposition_signing_payload.v1",
                "ai_irb_disposition_signing_payload_domain": "exo.decision_forum.ai_irb_disposition_signing_payload.v1",
                "chair_intervention_signing_payload_domain": "exo.decision_forum.chair_intervention_signing_payload.v1",
                "prepublication_domain": "exo.decision_forum.prepublication_package.v1",
                "publication_authorization_domain": "exo.decision_forum.publication_authorization_receipt.v1",
                "final_package_domain": "exo.decision_forum.peer_reviewed_protocol_package.v1",
                "artifact_manifest_domain": "exo.decision_forum.publication_artifact_manifest.v1",
                "execution_receipt_domain": "exo.decision_forum.protocol_execution_receipt.v1",
                "execution_receipt_chain_domain": "exo.decision_forum.protocol_execution_receipt_chain.v1",
                "genesis_evidence_bundle_domain": "exo.decision_forum.genesis_evidence_bundle.v1",
                "genesis_adoption_receipt_domain": "exo.decision_forum.genesis_adoption_receipt.v1",
                "final_root_normalization": "replace receipt_manifest.final_package_root with 32 zero bytes"
            },
            "publication_authorization_receipt": {
                "prepublication_root": hash_with('c'),
                "renderer_manifest_hash": hash_with('d'),
                "publisher_did": "did:exo:bob-stewart",
                "authorized_at": timestamp(1),
                "publisher_authority": {
                    "publisher_did": "did:exo:bob-stewart",
                    "signing_key_id": publisher_authority.signing_key_id,
                    "verification_key": publisher_authority.verification_key,
                    "authority_chain_hash": publisher_authority.authority_chain_hash
                },
                "signature": unsigned_signature_envelope("PublicationAuthorizationReceiptV1", 11)
            },
            "genesis_adoption_receipt": genesis_adoption_receipt(),
            "final_package_root": hash256()
        }
    });
    bind_package(package)
}

fn bind_package(mut package: Value) -> Value {
    let council_ids = [
        "did:exo:openai",
        "did:exo:anthropic",
        "did:exo:xai",
        "did:exo:gemini",
        "did:exo:independent",
    ];
    let ai_irb_ids = [
        "did:exo:irb-openai",
        "did:exo:irb-anthropic",
        "did:exo:irb-xai",
        "did:exo:irb-gemini",
        "did:exo:irb-independent",
    ];
    let protocol_version_hash = hash_fixture(
        "exo.decision_forum.protocol_version.v1",
        &package["protocol_identity"],
    );
    let seat_authority_registry = fixture_seat_authority_registry();
    let mut seat_contracts = BTreeMap::new();
    for (seat_id, seat_kind) in council_ids
        .iter()
        .map(|seat_id| (seat_id, "Council"))
        .chain(ai_irb_ids.iter().map(|seat_id| (seat_id, "AiIrb")))
    {
        let binding = seat_authority_registry
            .resolve("tenant-1", "DF-PROTOCOL-001", seat_id, seat_kind)
            .expect("fixture binding is independently verified");
        seat_contracts.insert(
            seat_id.to_string(),
            (
                binding.seat_attestation_hash.clone(),
                json!(binding.context_manifest_hash),
                json!(binding.seat_signing_key_id),
                json!(binding.seat_verification_key),
            ),
        );
    }
    let mut assignment_to_seat = BTreeMap::new();
    for assignment in package["review_bundle"]["assignments"]
        .as_array_mut()
        .expect("fixture assignments must be an array")
    {
        let seat_id = assignment["seat_id"]
            .as_str()
            .expect("fixture assignment seat")
            .to_owned();
        let contract = seat_contracts.get(&seat_id).expect("fixture seat contract");
        assignment["protocol_version_hash"] = json!(protocol_version_hash.clone());
        assignment["seat_attestation_hash"] = json!(contract.0.clone());
        assignment["context_manifest_hash"] = contract.1.clone();
        assignment_to_seat.insert(
            assignment["assignment_id"]
                .as_str()
                .expect("fixture assignment ID")
                .to_owned(),
            seat_id,
        );
    }

    for review in package["review_bundle"]["signed_reviews"]
        .as_array_mut()
        .expect("fixture reviews must be an array")
    {
        review["protocol_version_hash"] = json!(protocol_version_hash.clone());
    }
    let authorization_target_hash = authorization_target_fixture_hash(&package);
    for review in package["review_bundle"]["signed_reviews"]
        .as_array_mut()
        .expect("fixture reviews must be an array")
    {
        review["authorization_target_hash"] = json!(authorization_target_hash.clone());
        let seat_id = assignment_to_seat
            .get(
                review["assignment_id"]
                    .as_str()
                    .expect("fixture review assignment"),
            )
            .expect("fixture review assignment resolves");
        review["signature"] = sign_payload(
            "exo.decision_forum.peer_review_signing_payload.v1",
            "PeerReviewV1",
            &peer_review_signing_payload_fixture(review),
            fixture_seed_for_seat(seat_id),
        );
    }
    let review_bundle_hash = hash_fixture(
        "exo.decision_forum.review_bundle.v1",
        &package["review_bundle"],
    );
    for (votes_name, eligible_name, domain, target) in [
        (
            "council_votes",
            "council_eligible_set",
            "exo.decision_forum.council_disposition_signing_payload.v1",
            "CouncilDispositionV1",
        ),
        (
            "ai_irb_votes",
            "ai_irb_eligible_set",
            "exo.decision_forum.ai_irb_disposition_signing_payload.v1",
            "AiIrbDispositionV1",
        ),
    ] {
        let eligible_set_hash = hash_fixture(
            "exo.decision_forum.eligible_set.v1",
            &package["disposition_bundle"][eligible_name],
        );
        for vote in package["disposition_bundle"][votes_name]
            .as_array_mut()
            .expect("fixture votes must be arrays")
        {
            let seat_id = vote["seat_id"]
                .as_str()
                .expect("fixture vote seat")
                .to_owned();
            let contract = seat_contracts.get(&seat_id).expect("fixture vote contract");
            vote["authorization_target_hash"] = json!(authorization_target_hash.clone());
            vote["protocol_version_hash"] = json!(protocol_version_hash.clone());
            vote["review_bundle_hash"] = json!(review_bundle_hash.clone());
            vote["eligible_set_hash"] = json!(eligible_set_hash.clone());
            vote["seat_attestation_hash"] = json!(contract.0.clone());
            vote["context_manifest_hash"] = contract.1.clone();
            vote["signature"] = sign_payload(
                domain,
                target,
                &disposition_signing_payload_fixture(vote),
                fixture_seed_for_seat(&seat_id),
            );
        }
    }
    let council_quorum_hashes: Vec<Value> = council_ids
        .iter()
        .map(|seat| json!(seat_contracts[*seat].0.clone()))
        .collect();
    let ai_irb_quorum_hashes: Vec<Value> = ai_irb_ids
        .iter()
        .map(|seat| json!(seat_contracts[*seat].0.clone()))
        .collect();
    let quorum_evidence_classes =
        package["evidence_manifest"]["independent_evidence_classes"].clone();
    for proof in package["disposition_bundle"]["quorum_proofs"]
        .as_array_mut()
        .expect("fixture quorum proofs must be an array")
    {
        let body = proof["seat_kind"].as_str().expect("fixture quorum body");
        let hashes = if body == "Council" {
            council_quorum_hashes.clone()
        } else {
            ai_irb_quorum_hashes.clone()
        };
        proof["eligible_seat_hashes"] = json!(hashes.clone());
        proof["approve_seat_hashes"] = json!(hashes);
        proof["provider_classes"] = json!(["OpenAI", "Anthropic", "xAI", "AlphabetGoogleGemini"]);
        proof["evidence_classes"] = quorum_evidence_classes.clone();
        proof["proof_hash"] = json!(quorum_proof_fixture_hash(proof));
    }
    let chair_scope_hash = hash_fixture(
        "exo.decision_forum.protocol_envelope.v1",
        &package["protocol_envelope"],
    );
    let chair_authority = package["protocol_identity"]["chair_authority"].clone();
    for intervention in package["disposition_bundle"]["chair_interventions"]
        .as_array_mut()
        .expect("fixture Chair interventions must be an array")
    {
        intervention["scope_hash"] = json!(chair_scope_hash.clone());
        intervention["authorization_target_hash"] = json!(authorization_target_hash.clone());
        intervention["protocol_version_hash"] = json!(protocol_version_hash.clone());
        intervention["signature"] = sign_payload(
            "exo.decision_forum.chair_intervention_signing_payload.v1",
            "ChairInterventionV1",
            &chair_intervention_signing_payload_fixture(intervention),
            12,
        );
        assert_eq!(
            intervention["signature"]["signing_key_id"],
            chair_authority["signing_key_id"]
        );
    }
    let prepublication_root = prepublication_fixture_hash(&package);
    let publication = &mut package["receipt_manifest"]["publication_authorization_receipt"];
    publication["prepublication_root"] = json!(prepublication_root);
    let publication_payload = publication_authorization_signing_payload_fixture(publication);
    let publication_signature = sign_payload(
        "exo.decision_forum.publication_authorization_receipt.v1",
        "PublicationAuthorizationReceiptV1",
        &publication_payload,
        11,
    );
    publication["signature"] = publication_signature;
    let final_package_root = normalized_final_fixture_hash(&package);
    package["receipt_manifest"]["final_package_root"] = json!(final_package_root);
    package
}

fn fully_resign_with_untrusted_seat_keys(package: &Value) -> Value {
    let mut attacked = package.clone();
    let mut attacker_seats = BTreeMap::new();
    for (index, (seat_did, seat_kind, _, _, authority_scope, _, _, _, _)) in
        fixture_seat_rows().into_iter().enumerate()
    {
        let seat_seed = 31_u8
            .checked_add(index as u8)
            .expect("fixture attacker seat seed");
        let controller_seed = 51_u8
            .checked_add(index as u8)
            .expect("fixture attacker controller seed");
        let roster_name = if seat_kind == "Council" {
            "council_seat_attestations"
        } else {
            "ai_irb_seat_attestations"
        };
        let attestation = attacked["review_bundle"][roster_name]
            .as_object_mut()
            .expect("fixture attacker roster")
            .values_mut()
            .find(|attestation| attestation["seat_id"] == seat_did)
            .expect("fixture attacker seat attestation");
        let (seat_signing_key_id, seat_verification_key) = fixture_key_material(seat_seed);
        let attacker_chain_hash = hash_fixture(
            "exo.decision_forum.attacker_seat_authority_chain.v1",
            &json!({ "seat_did": seat_did, "seat_kind": seat_kind }),
        );
        attestation["signing_key_id"] = json!(seat_signing_key_id);
        attestation["verification_key"] = json!(seat_verification_key);
        attestation["authority_scope"] = json!(authority_scope);
        attestation["authority_chain_hash"] = json!(attacker_chain_hash);
        attestation["signature"] = sign_payload(
            "exo.decision_forum.seat_attestation_signing_payload.v1",
            "SeatAttestationV1",
            &seat_attestation_signing_payload_fixture(attestation),
            controller_seed,
        );
        let attestation_hash = hash_fixture("exo.decision_forum.seat_attestation.v1", attestation);
        attacker_seats.insert(
            seat_did.to_owned(),
            (
                seat_kind.to_owned(),
                seat_seed,
                attestation_hash,
                attestation["context_manifest_hash"].clone(),
                attestation["signing_key_id"].clone(),
                attestation["verification_key"].clone(),
                attestation["authority_chain_hash"].clone(),
            ),
        );
    }

    for reference in attacked["disposition_bundle"]["authority_chain"]
        .as_array_mut()
        .expect("fixture attacker authority chain")
    {
        if reference["binding_kind"] != "SeatAuthority" {
            continue;
        }
        let seat_did = reference["actor_did"]
            .as_str()
            .expect("fixture attacker authority seat")
            .to_owned();
        let seat = attacker_seats
            .get(&seat_did)
            .expect("fixture attacker seat authority");
        reference["signing_key_id"] = seat.4.clone();
        reference["verification_key"] = seat.5.clone();
        reference["authority_chain_hash"] = seat.6.clone();
    }

    let mut assignment_to_seat = BTreeMap::new();
    for assignment in attacked["review_bundle"]["assignments"]
        .as_array_mut()
        .expect("fixture attacker assignments")
    {
        let seat_did = assignment["seat_id"]
            .as_str()
            .expect("fixture attacker assignment seat")
            .to_owned();
        let seat = attacker_seats
            .get(&seat_did)
            .expect("fixture attacker assignment binding");
        assignment["seat_attestation_hash"] = json!(seat.2);
        assignment["context_manifest_hash"] = seat.3.clone();
        assignment_to_seat.insert(
            assignment["assignment_id"]
                .as_str()
                .expect("fixture attacker assignment ID")
                .to_owned(),
            seat_did,
        );
    }
    for review in attacked["review_bundle"]["signed_reviews"]
        .as_array_mut()
        .expect("fixture attacker reviews")
    {
        let seat_did = assignment_to_seat
            .get(
                review["assignment_id"]
                    .as_str()
                    .expect("fixture attacker review assignment"),
            )
            .expect("fixture attacker review seat");
        review["signature"] =
            unsigned_signature_envelope("PeerReviewV1", attacker_seats[seat_did].1);
        review["authorization_target_hash"] = json!(repeated_hex('0', 64));
    }
    let authorization_target_hash = authorization_target_fixture_hash(&attacked);
    for review in attacked["review_bundle"]["signed_reviews"]
        .as_array_mut()
        .expect("fixture attacker reviews")
    {
        let seat_did = assignment_to_seat
            .get(
                review["assignment_id"]
                    .as_str()
                    .expect("fixture attacker review assignment"),
            )
            .expect("fixture attacker review seat");
        review["authorization_target_hash"] = json!(authorization_target_hash);
        review["signature"] = sign_payload(
            "exo.decision_forum.peer_review_signing_payload.v1",
            "PeerReviewV1",
            &peer_review_signing_payload_fixture(review),
            attacker_seats[seat_did].1,
        );
    }
    let review_bundle_hash = hash_fixture(
        "exo.decision_forum.review_bundle.v1",
        &attacked["review_bundle"],
    );
    for (votes_name, domain, target) in [
        (
            "council_votes",
            "exo.decision_forum.council_disposition_signing_payload.v1",
            "CouncilDispositionV1",
        ),
        (
            "ai_irb_votes",
            "exo.decision_forum.ai_irb_disposition_signing_payload.v1",
            "AiIrbDispositionV1",
        ),
    ] {
        for vote in attacked["disposition_bundle"][votes_name]
            .as_array_mut()
            .expect("fixture attacker votes")
        {
            let seat_did = vote["seat_id"]
                .as_str()
                .expect("fixture attacker vote seat")
                .to_owned();
            let seat = &attacker_seats[&seat_did];
            vote["authorization_target_hash"] = json!(authorization_target_hash);
            vote["review_bundle_hash"] = json!(review_bundle_hash);
            vote["seat_attestation_hash"] = json!(seat.2);
            vote["context_manifest_hash"] = seat.3.clone();
            vote["signature"] = sign_payload(
                domain,
                target,
                &disposition_signing_payload_fixture(vote),
                seat.1,
            );
        }
    }
    for proof in attacked["disposition_bundle"]["quorum_proofs"]
        .as_array_mut()
        .expect("fixture attacker quorum proofs")
    {
        let seat_kind = proof["seat_kind"]
            .as_str()
            .expect("fixture attacker quorum body")
            .to_owned();
        let hashes: Vec<Value> = attacker_seats
            .values()
            .filter(|seat| seat.0 == seat_kind)
            .map(|seat| json!(seat.2))
            .collect();
        proof["eligible_seat_hashes"] = json!(hashes);
        proof["approve_seat_hashes"] = json!(hashes);
        proof["proof_hash"] = json!(quorum_proof_fixture_hash(proof));
    }
    for intervention in attacked["disposition_bundle"]["chair_interventions"]
        .as_array_mut()
        .expect("fixture attacker Chair interventions")
    {
        intervention["authorization_target_hash"] = json!(authorization_target_hash);
        intervention["signature"] = sign_payload(
            "exo.decision_forum.chair_intervention_signing_payload.v1",
            "ChairInterventionV1",
            &chair_intervention_signing_payload_fixture(intervention),
            12,
        );
    }
    let prepublication_root = prepublication_fixture_hash(&attacked);
    let publication = &mut attacked["receipt_manifest"]["publication_authorization_receipt"];
    publication["prepublication_root"] = json!(prepublication_root);
    publication["signature"] = sign_payload(
        "exo.decision_forum.publication_authorization_receipt.v1",
        "PublicationAuthorizationReceiptV1",
        &publication_authorization_signing_payload_fixture(publication),
        11,
    );
    attacked["receipt_manifest"]["final_package_root"] =
        json!(normalized_final_fixture_hash(&attacked));
    attacked
}

fn hash_fixture(domain: &str, value: &Value) -> String {
    exo_core::hash::hash_structured(&(domain, value))
        .expect("fixture must encode as CBOR")
        .to_string()
}

fn authorization_target_fixture(package: &Value) -> Value {
    let mut target = serde_json::Map::new();
    for field in [
        "schema_version",
        "protocol_identity",
        "protocol_document",
        "protocol_envelope",
        "evidence_manifest",
        "monitoring_plan",
        "systemic_learning_manifest",
        "commercial_boundary",
    ] {
        target.insert(field.to_owned(), package[field].clone());
    }
    let mut review_bundle = package["review_bundle"].clone();
    for review in review_bundle["signed_reviews"]
        .as_array_mut()
        .expect("fixture reviews must be arrays")
    {
        review["authorization_target_hash"] = json!(repeated_hex('0', 64));
        review["signature"]["signed_payload_hash"] = json!(repeated_hex('0', 64));
        review["signature"]["signature"] = json!(repeated_hex('0', 128));
    }
    target.insert("review_bundle".to_owned(), review_bundle);
    let mut receipts = serde_json::Map::new();
    for field in [
        "preauthorization_lifecycle_receipts",
        "prior_execution_receipt_chain",
        "genesis_adoption_receipt",
    ] {
        receipts.insert(field.to_owned(), package["receipt_manifest"][field].clone());
    }
    target.insert("receipt_commitments".to_owned(), Value::Object(receipts));
    Value::Object(target)
}

fn authorization_target_fixture_hash(package: &Value) -> String {
    hash_fixture(
        "exo.decision_forum.protocol_authorization_target.v1",
        &authorization_target_fixture(package),
    )
}

fn peer_review_signing_payload_fixture(review: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    for field in [
        "review_id",
        "assignment_id",
        "protocol_version_hash",
        "criteria_results_hash",
        "review_body_hash",
        "disposition",
        "sealed_at",
        "authorization_target_hash",
    ] {
        payload.insert(field.to_owned(), review[field].clone());
    }
    Value::Object(payload)
}

fn disposition_signing_payload_fixture(disposition: &Value) -> Value {
    let mut body = disposition.clone();
    body.as_object_mut()
        .expect("fixture disposition must be an object")
        .remove("signature");
    body
}

fn chair_intervention_signing_payload_fixture(intervention: &Value) -> Value {
    let mut body = intervention.clone();
    body.as_object_mut()
        .expect("fixture Chair intervention must be an object")
        .remove("signature");
    body
}

fn publication_authorization_signing_payload_fixture(publication: &Value) -> Value {
    json!({
        "prepublication_root": publication["prepublication_root"],
        "renderer_manifest_hash": publication["renderer_manifest_hash"],
        "publisher_did": publication["publisher_did"],
        "authorized_at": publication["authorized_at"]
    })
}

fn quorum_proof_fixture_hash(proof: &Value) -> String {
    let mut normalized = proof.clone();
    normalized["proof_hash"] = json!(repeated_hex('0', 64));
    hash_fixture(
        "exo.decision_forum.eligible_unanimity_quorum_proof.v1",
        &normalized,
    )
}

fn prepublication_fixture_hash(package: &Value) -> String {
    let mut normalized = package.clone();
    normalized["receipt_manifest"]["publication_authorization_receipt"] = Value::Null;
    normalized["receipt_manifest"]["final_package_root"] = json!(repeated_hex('0', 64));
    hash_fixture("exo.decision_forum.prepublication_package.v1", &normalized)
}

fn normalized_final_fixture_hash(package: &Value) -> String {
    let mut normalized = package.clone();
    normalized["receipt_manifest"]["final_package_root"] = json!(repeated_hex('0', 64));
    hash_fixture(
        "exo.decision_forum.peer_reviewed_protocol_package.v1",
        &normalized,
    )
}

fn execution_receipt_signing_payload_fixture(receipt: &Value) -> Value {
    let mut body = receipt.clone();
    body.as_object_mut()
        .expect("fixture execution receipt must be an object")
        .remove("signature");
    body
}

fn execution_receipt_hash(receipt: &Value) -> String {
    hash_fixture("exo.decision_forum.protocol_execution_receipt.v1", receipt)
}

fn execution_chain_root(chain: &Value) -> String {
    let mut normalized = chain.clone();
    normalized["chain_root"] = json!(repeated_hex('0', 64));
    hash_fixture(
        "exo.decision_forum.protocol_execution_receipt_chain.v1",
        &normalized,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedPackageRoot {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: String,
    final_package_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedExecutionChain {
    tenant_id: String,
    protocol_id: String,
    protocol_version_hash: String,
    authorized_package_root: String,
    previous_chain_root: String,
    predecessor_terminal_receipt_hash: String,
    predecessor_terminal_sequence: u64,
    first_sequence: u64,
    terminal_receipt_hash: String,
    terminal_sequence: u64,
    receipt_count: u64,
    chain_root: String,
}

fn historical_verified_package_root() -> VerifiedPackageRoot {
    VerifiedPackageRoot {
        tenant_id: "tenant-1".to_owned(),
        protocol_id: "DF-PROTOCOL-001".to_owned(),
        protocol_version_hash: hash_with('9'),
        final_package_root: hash_with('8'),
    }
}

fn create_execution_chain(
    verified_root: &VerifiedPackageRoot,
    predecessor: Option<&VerifiedExecutionChain>,
    signer_did: &str,
    authority_registry: &VerifiedAuthorityRegistryV1,
) -> Value {
    let (previous_chain_root, predecessor_terminal_receipt_hash, predecessor_terminal_sequence) =
        predecessor.map_or_else(
            || (hash_with('0'), hash_with('0'), 0_u64),
            |chain| {
                (
                    chain.chain_root.clone(),
                    chain.terminal_receipt_hash.clone(),
                    chain.terminal_sequence,
                )
            },
        );
    let first_sequence = predecessor_terminal_sequence
        .checked_add(1)
        .expect("fixture sequence must not overflow");
    let authority = authority_registry
        .resolve(
            &verified_root.tenant_id,
            &verified_root.protocol_id,
            signer_did,
            "ProtocolExecutionReceiptV1",
        )
        .expect("fixture execution authority is independently verified");
    let signer_seed = fixture_authority_seed(signer_did, "ProtocolExecutionReceiptV1");
    let mut receipts = Vec::new();
    let mut previous = predecessor_terminal_receipt_hash.clone();
    for (offset, kind, payload_character) in [
        (0_u64, "ActionExecuted", '1'),
        (1_u64, "ContinuingReview", '2'),
        (2_u64, "AdverseEvent", '3'),
    ] {
        let sequence = first_sequence
            .checked_add(offset)
            .expect("fixture sequence must not overflow");
        let mut receipt = json!({
            "receipt_id": format!("00000000-0000-4000-8{signer_seed:03}-{sequence:012}"),
            "tenant_id": verified_root.tenant_id,
            "protocol_id": verified_root.protocol_id,
            "protocol_version_hash": verified_root.protocol_version_hash,
            "authorized_package_root": verified_root.final_package_root,
            "sequence": sequence,
            "receipt_kind": kind,
            "previous_receipt_hash": previous,
            "payload_hash": hash_with(payload_character),
            "idempotency_key_hash": hash_with(char::from_digit((offset + 4) as u32, 16).expect("fixture offset is hexadecimal")),
            "occurred_at": timestamp(sequence),
            "signer_did": signer_did,
            "signature": unsigned_signature_envelope("ProtocolExecutionReceiptV1", signer_seed)
        });
        receipt["signature"] = sign_payload(
            "exo.decision_forum.protocol_execution_receipt.v1",
            "ProtocolExecutionReceiptV1",
            &execution_receipt_signing_payload_fixture(&receipt),
            signer_seed,
        );
        previous = execution_receipt_hash(&receipt);
        receipts.push(receipt);
    }
    let terminal_sequence = first_sequence
        .checked_add(2)
        .expect("fixture sequence must not overflow");
    let mut chain = json!({
        "schema_version": 1,
        "tenant_id": verified_root.tenant_id,
        "protocol_id": verified_root.protocol_id,
        "protocol_version_hash": verified_root.protocol_version_hash,
        "authorized_package_root": verified_root.final_package_root,
        "previous_chain_root": previous_chain_root,
        "predecessor_terminal_receipt_hash": predecessor_terminal_receipt_hash,
        "predecessor_terminal_sequence": predecessor_terminal_sequence,
        "first_sequence": first_sequence,
        "signer_authorities": {
            (signer_did): authority_reference(authority)
        },
        "receipts": receipts,
        "terminal_receipt_hash": previous,
        "terminal_sequence": terminal_sequence,
        "receipt_count": 3,
        "chain_root": repeated_hex('0', 64)
    });
    chain["chain_root"] = json!(execution_chain_root(&chain));
    chain
}

fn predecessor_execution_chain(authority_registry: &VerifiedAuthorityRegistryV1) -> Value {
    create_execution_chain(
        &historical_verified_package_root(),
        None,
        "did:exo:executor-13",
        authority_registry,
    )
}

fn prior_execution_chain_reference(chain: &VerifiedExecutionChain) -> Value {
    json!({
        "tenant_id": chain.tenant_id,
        "protocol_id": chain.protocol_id,
        "prior_protocol_version_hash": chain.protocol_version_hash,
        "authorized_package_root": chain.authorized_package_root,
        "previous_chain_root": chain.previous_chain_root,
        "predecessor_terminal_receipt_hash": chain.predecessor_terminal_receipt_hash,
        "predecessor_terminal_sequence": chain.predecessor_terminal_sequence,
        "first_sequence": chain.first_sequence,
        "chain_root": chain.chain_root,
        "terminal_receipt_hash": chain.terminal_receipt_hash,
        "terminal_sequence": chain.terminal_sequence,
        "receipt_count": chain.receipt_count
    })
}

fn current_execution_chain(
    verified_root: &VerifiedPackageRoot,
    predecessor: &VerifiedExecutionChain,
    authority_registry: &VerifiedAuthorityRegistryV1,
) -> Value {
    create_execution_chain(
        verified_root,
        Some(predecessor),
        "did:exo:executor-14",
        authority_registry,
    )
}

fn successor_package(package: &Value, completed_chain: &VerifiedExecutionChain) -> Value {
    let mut successor = package.clone();
    successor["protocol_identity"]["version"] = json!(
        package["protocol_identity"]["version"]
            .as_u64()
            .expect("fixture version")
            + 1
    );
    successor["protocol_identity"]["prior_version_hash"] = json!(hash_fixture(
        "exo.decision_forum.protocol_version.v1",
        &package["protocol_identity"],
    ));
    successor["receipt_manifest"]["prior_execution_receipt_chain"] =
        prior_execution_chain_reference(completed_chain);
    bind_package(successor)
}

struct ExecutionChainExpectation<'a> {
    verified_package_root: &'a VerifiedPackageRoot,
    predecessor_chain_root: &'a str,
    predecessor_terminal_receipt_hash: &'a str,
    predecessor_terminal_sequence: u64,
    allowed_receipt_kinds: BTreeSet<&'a str>,
    expected_receipt_count: u64,
}

fn verify_execution_chain(
    chain: &Value,
    expected: &ExecutionChainExpectation<'_>,
    authority_registry: &VerifiedAuthorityRegistryV1,
) -> Result<VerifiedExecutionChain, String> {
    let verified_root = expected.verified_package_root;
    let expected_first_sequence = expected
        .predecessor_terminal_sequence
        .checked_add(1)
        .ok_or_else(|| "execution sequence overflow".to_owned())?;
    if chain["tenant_id"] != verified_root.tenant_id
        || chain["protocol_id"] != verified_root.protocol_id
        || chain["protocol_version_hash"] != verified_root.protocol_version_hash
        || chain["authorized_package_root"] != verified_root.final_package_root
        || chain["previous_chain_root"] != expected.predecessor_chain_root
        || chain["predecessor_terminal_receipt_hash"] != expected.predecessor_terminal_receipt_hash
        || chain["predecessor_terminal_sequence"] != expected.predecessor_terminal_sequence
        || chain["first_sequence"] != expected_first_sequence
        || chain["chain_root"] != execution_chain_root(chain)
    {
        return Err(
            "execution chain identity, predecessor, sequence, root, or authorization mismatch"
                .to_owned(),
        );
    }
    let receipts = chain["receipts"]
        .as_array()
        .ok_or_else(|| "execution receipts must be an array".to_owned())?;
    if receipts.len() as u64 != expected.expected_receipt_count
        || chain["receipt_count"] != expected.expected_receipt_count
    {
        return Err("execution receipt count mismatch".to_owned());
    }
    let embedded_authorities = chain["signer_authorities"]
        .as_object()
        .ok_or_else(|| "execution signer authorities must be an object".to_owned())?;
    for (actor_did, embedded) in embedded_authorities {
        let trusted = authority_registry.resolve(
            &verified_root.tenant_id,
            &verified_root.protocol_id,
            actor_did,
            "ProtocolExecutionReceiptV1",
        )?;
        if embedded != &authority_reference(trusted) {
            return Err("execution signer authority differs from trusted registry".to_owned());
        }
    }
    let mut previous = json!(expected.predecessor_terminal_receipt_hash);
    let mut receipt_ids = BTreeSet::new();
    let mut idempotency_keys = BTreeSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let expected_sequence = expected_first_sequence
            .checked_add(index as u64)
            .ok_or_else(|| "execution sequence overflow".to_owned())?;
        if receipt["sequence"] != expected_sequence
            || receipt["tenant_id"] != verified_root.tenant_id
            || receipt["protocol_id"] != verified_root.protocol_id
            || receipt["protocol_version_hash"] != verified_root.protocol_version_hash
            || receipt["authorized_package_root"] != verified_root.final_package_root
            || receipt["previous_receipt_hash"] != previous
        {
            return Err("execution receipt identity, sequence, root, or link mismatch".to_owned());
        }
        let kind = receipt["receipt_kind"]
            .as_str()
            .ok_or_else(|| "execution receipt kind missing".to_owned())?;
        if !expected.allowed_receipt_kinds.contains(kind) {
            return Err("execution receipt kind is not allowed".to_owned());
        }
        if !receipt_ids.insert(
            receipt["receipt_id"]
                .as_str()
                .ok_or_else(|| "execution receipt ID missing".to_owned())?
                .to_owned(),
        ) || !idempotency_keys.insert(
            receipt["idempotency_key_hash"]
                .as_str()
                .ok_or_else(|| "execution idempotency key missing".to_owned())?
                .to_owned(),
        ) {
            return Err("execution receipt replay conflict".to_owned());
        }
        let signer = receipt["signer_did"]
            .as_str()
            .ok_or_else(|| "execution receipt signer missing".to_owned())?;
        let authority = authority_registry.resolve(
            &verified_root.tenant_id,
            &verified_root.protocol_id,
            signer,
            "ProtocolExecutionReceiptV1",
        )?;
        if embedded_authorities.get(signer) != Some(&authority_reference(authority))
            || authority.signing_key_id
                != hash_fixture(
                    "exo.decision_forum.verification_key_id.v1",
                    &json!({ "verification_key": authority.verification_key }),
                )
        {
            return Err("execution signer authority or key attestation mismatch".to_owned());
        }
        verify_signed_payload(
            "exo.decision_forum.protocol_execution_receipt.v1",
            "ProtocolExecutionReceiptV1",
            &execution_receipt_signing_payload_fixture(receipt),
            &receipt["signature"],
            &authority.signing_key_id,
            &authority.verification_key,
        )?;
        previous = json!(execution_receipt_hash(receipt));
    }
    let expected_terminal_sequence = expected_first_sequence
        .checked_add(expected.expected_receipt_count.saturating_sub(1))
        .ok_or_else(|| "execution terminal sequence overflow".to_owned())?;
    if chain["terminal_receipt_hash"] != previous
        || chain["terminal_sequence"] != expected_terminal_sequence
        || receipts
            .last()
            .and_then(|receipt| receipt["sequence"].as_u64())
            != Some(expected_terminal_sequence)
    {
        return Err("execution chain terminal receipt or sequence mismatch".to_owned());
    }
    Ok(VerifiedExecutionChain {
        tenant_id: verified_root.tenant_id.clone(),
        protocol_id: verified_root.protocol_id.clone(),
        protocol_version_hash: verified_root.protocol_version_hash.clone(),
        authorized_package_root: verified_root.final_package_root.clone(),
        previous_chain_root: expected.predecessor_chain_root.to_owned(),
        predecessor_terminal_receipt_hash: expected.predecessor_terminal_receipt_hash.to_owned(),
        predecessor_terminal_sequence: expected.predecessor_terminal_sequence,
        first_sequence: expected_first_sequence,
        terminal_receipt_hash: chain["terminal_receipt_hash"]
            .as_str()
            .ok_or_else(|| "execution terminal receipt hash missing".to_owned())?
            .to_owned(),
        terminal_sequence: expected_terminal_sequence,
        receipt_count: expected.expected_receipt_count,
        chain_root: chain["chain_root"]
            .as_str()
            .ok_or_else(|| "execution chain root missing".to_owned())?
            .to_owned(),
    })
}

fn fixture_verified_predecessor(
    authority_registry: &VerifiedAuthorityRegistryV1,
) -> Result<VerifiedExecutionChain, String> {
    let root = historical_verified_package_root();
    let chain = predecessor_execution_chain(authority_registry);
    verify_execution_chain(
        &chain,
        &ExecutionChainExpectation {
            verified_package_root: &root,
            predecessor_chain_root: &hash_with('0'),
            predecessor_terminal_receipt_hash: &hash_with('0'),
            predecessor_terminal_sequence: 0,
            allowed_receipt_kinds: ["ActionExecuted", "ContinuingReview", "AdverseEvent"]
                .into_iter()
                .collect(),
            expected_receipt_count: 3,
        },
        authority_registry,
    )
}

fn verify_prior_execution_reference(
    reference: &Value,
    verified_chain: &VerifiedExecutionChain,
) -> Result<(), String> {
    if reference != &prior_execution_chain_reference(verified_chain) {
        return Err(
            "successor prior-chain reference does not exactly match verified chain".to_owned(),
        );
    }
    Ok(())
}

fn resign_and_relink_execution_chain(
    chain: &mut Value,
    authority: &VerifiedAuthorityBindingV1,
    signing_seed: u8,
) {
    chain["signer_authorities"] = json!({
        (authority.actor_did.clone()): authority_reference(authority)
    });
    let mut previous = chain["predecessor_terminal_receipt_hash"]
        .as_str()
        .expect("fixture predecessor terminal hash")
        .to_owned();
    let (first_sequence, terminal_sequence, receipt_count) = {
        let receipts = chain["receipts"]
            .as_array_mut()
            .expect("fixture execution receipts must be an array");
        for receipt in receipts.iter_mut() {
            receipt["signer_did"] = json!(authority.actor_did);
            receipt["previous_receipt_hash"] = json!(previous);
            receipt["signature"] =
                unsigned_signature_envelope("ProtocolExecutionReceiptV1", signing_seed);
            receipt["signature"] = sign_payload(
                "exo.decision_forum.protocol_execution_receipt.v1",
                "ProtocolExecutionReceiptV1",
                &execution_receipt_signing_payload_fixture(receipt),
                signing_seed,
            );
            previous = execution_receipt_hash(receipt);
        }
        (
            receipts.first().expect("fixture first execution receipt")["sequence"].clone(),
            receipts.last().expect("fixture terminal execution receipt")["sequence"].clone(),
            receipts.len() as u64,
        )
    };
    chain["first_sequence"] = first_sequence;
    chain["terminal_sequence"] = terminal_sequence;
    chain["terminal_receipt_hash"] = json!(previous);
    chain["receipt_count"] = json!(receipt_count);
    chain["chain_root"] = json!(execution_chain_root(chain));
}

fn compile_schema(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .unwrap_or_else(|error| panic!("Draft 2020-12 schema meta-validation failed: {error}"))
}

fn assert_invalid(validator: &JSONSchema, instance: &Value, case: &str) {
    assert!(
        !validator.is_valid(instance),
        "adversarial case validated: {case}"
    );
}

fn string_set(values: &Value, label: &str) -> Result<BTreeSet<String>, String> {
    values
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} must contain strings"))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IndependentEvidenceClass {
    DeterministicTest,
    ReproducibleBenchmark,
    AttestedExecution,
    IndependentHumanReview,
    FormalVerification,
    ExternalAudit,
    IndependentNonProviderEvidence,
}

impl TryFrom<&str> for IndependentEvidenceClass {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "DeterministicTest" => Ok(Self::DeterministicTest),
            "ReproducibleBenchmark" => Ok(Self::ReproducibleBenchmark),
            "AttestedExecution" => Ok(Self::AttestedExecution),
            "IndependentHumanReview" => Ok(Self::IndependentHumanReview),
            "FormalVerification" => Ok(Self::FormalVerification),
            "ExternalAudit" => Ok(Self::ExternalAudit),
            "IndependentNonProviderEvidence" => Ok(Self::IndependentNonProviderEvidence),
            "ProviderModelJudgment" => {
                Err("ProviderModelJudgment cannot satisfy an independent evidence floor".to_owned())
            }
            _ => Err(format!("unknown independent evidence class {value}")),
        }
    }
}

fn independent_evidence_set(
    values: &Value,
    label: &str,
) -> Result<BTreeSet<IndependentEvidenceClass>, String> {
    values
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))?
        .iter()
        .map(|value| {
            IndependentEvidenceClass::try_from(
                value
                    .as_str()
                    .ok_or_else(|| format!("{label} must contain strings"))?,
            )
        })
        .collect()
}

fn roster_values<'a>(package: &'a Value, body: &str) -> Result<Vec<&'a Value>, String> {
    package["review_bundle"][body]
        .as_object()
        .ok_or_else(|| format!("{body} must be an object"))
        .map(|roster| roster.values().collect())
}

fn assert_binding_semantics(
    package: &Value,
    authority_registry: &VerifiedAuthorityRegistryV1,
    seat_authority_registry: &VerifiedSeatAuthorityRegistryV1,
    verified_predecessor: Option<&VerifiedExecutionChain>,
) -> Result<VerifiedPackageRoot, String> {
    if package["disposition_bundle"]["binding_mode"] != "BindingInsideRatifiedEnvelope" {
        return Err("advisory package cannot produce a verified execution root".to_owned());
    }
    if package["protocol_identity"]["lifecycle_state"] != "Approved" {
        return Err("binding requires lifecycle_state Approved".to_owned());
    }
    let tenant_id = package["protocol_identity"]["tenant_id"]
        .as_str()
        .ok_or_else(|| "tenant ID missing".to_owned())?;
    let protocol_id = package["protocol_identity"]["protocol_id"]
        .as_str()
        .ok_or_else(|| "protocol ID missing".to_owned())?;
    let verification_at = timestamp(1);

    let evidence = independent_evidence_set(
        &package["evidence_manifest"]["independent_evidence_classes"],
        "independent evidence classes",
    )?;
    if evidence.len() < 2
        || !evidence.contains(&IndependentEvidenceClass::IndependentNonProviderEvidence)
    {
        return Err(
            "binding requires two genuinely independent evidence classes including IndependentNonProviderEvidence"
                .to_owned(),
        );
    }

    let expected_authorization_target = authorization_target_fixture_hash(package);
    let assignments = package["review_bundle"]["assignments"]
        .as_array()
        .ok_or_else(|| "assignments must be an array".to_owned())?;
    if assignments.len() != 10 {
        return Err("binding requires exactly ten review assignments".to_owned());
    }
    let mut assignment_seats = BTreeMap::new();
    for assignment in assignments {
        let assignment_id = assignment["assignment_id"]
            .as_str()
            .ok_or_else(|| "assignment ID missing".to_owned())?
            .to_owned();
        let seat_id = assignment["seat_id"]
            .as_str()
            .ok_or_else(|| "assignment seat missing".to_owned())?
            .to_owned();
        if assignment_seats.insert(assignment_id, seat_id).is_some() {
            return Err("duplicate assignment ID".to_owned());
        }
    }
    let council_roles: BTreeSet<String> = assignments
        .iter()
        .filter(|assignment| assignment["seat_kind"] == "Council")
        .filter_map(|assignment| assignment["review_role"].as_str().map(str::to_owned))
        .collect();
    let ai_irb_roles: BTreeSet<String> = assignments
        .iter()
        .filter(|assignment| assignment["seat_kind"] == "AiIrb")
        .filter_map(|assignment| assignment["review_role"].as_str().map(str::to_owned))
        .collect();
    if council_roles
        != [
            "Architecture",
            "Governance",
            "Legal",
            "Operations",
            "Security",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    {
        return Err("Council assignments must cover five distinct disciplines".to_owned());
    }
    if ai_irb_roles
        != [
            "AdverseEvent",
            "CorrectiveAction",
            "Monitoring",
            "ProgressiveEvent",
            "RiskBenefit",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    {
        return Err("AI-IRB assignments must cover five distinct review functions".to_owned());
    }

    let mut all_authorization_targets = BTreeSet::new();
    let mut trusted_signing_authority_by_seat = BTreeMap::new();
    let mut body_keys = Vec::new();
    let mut body_contexts = Vec::new();
    let provider_controller_dids: BTreeSet<String> = seat_authority_registry
        .entries
        .values()
        .filter(|binding| binding.provider_class != "IndependentNonProvider")
        .map(|binding| binding.controller_did.clone())
        .collect();
    let mut controller_provider_classes = BTreeMap::<String, String>::new();
    let prohibited_independent_controllers: BTreeSet<String> =
        package["protocol_identity"]["co_pi_dids"]
            .as_array()
            .ok_or_else(|| "Co-PI DIDs must be an array".to_owned())?
            .iter()
            .filter_map(|did| did.as_str().map(str::to_owned))
            .chain(
                package["protocol_identity"]["chair_did"]
                    .as_str()
                    .map(str::to_owned),
            )
            .collect();
    for (roster_name, eligible_name, votes_name, body) in [
        (
            "council_seat_attestations",
            "council_eligible_set",
            "council_votes",
            "Council",
        ),
        (
            "ai_irb_seat_attestations",
            "ai_irb_eligible_set",
            "ai_irb_votes",
            "AiIrb",
        ),
    ] {
        let roster = roster_values(package, roster_name)?;
        let roster_ids: BTreeSet<String> = roster
            .iter()
            .map(|attestation| {
                attestation["seat_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{body} roster seat_id missing"))
            })
            .collect::<Result<_, _>>()?;
        let eligible = string_set(
            &package["disposition_bundle"][eligible_name],
            &format!("{body} eligible set"),
        )?;
        let votes = package["disposition_bundle"][votes_name]
            .as_array()
            .ok_or_else(|| format!("{body} votes must be an array"))?;
        let vote_ids: BTreeSet<String> = votes
            .iter()
            .map(|vote| {
                if vote["choice"] != "Approve" {
                    return Err(format!("{body} binding vote is not Approve"));
                }
                let target = vote["authorization_target_hash"]
                    .as_str()
                    .ok_or_else(|| format!("{body} authorization target missing"))?;
                if target != expected_authorization_target.as_str() {
                    return Err(format!(
                        "{body} vote does not bind the computed authorization target"
                    ));
                }
                all_authorization_targets.insert(target.to_owned());
                vote["seat_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{body} vote seat_id missing"))
            })
            .collect::<Result<_, _>>()?;
        if roster_ids.len() != 5 || eligible != roster_ids || vote_ids != roster_ids {
            return Err(format!(
                "{body} roster, eligible set, and vote seat IDs differ"
            ));
        }

        let keys: BTreeSet<String> = roster
            .iter()
            .map(|attestation| {
                attestation["signing_key_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        let contexts: BTreeSet<String> = roster
            .iter()
            .map(|attestation| {
                attestation["context_manifest_hash"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        if keys.len() != 5 || contexts.len() != 5 {
            return Err(format!("{body} keys and contexts must be unique"));
        }
        for attestation in &roster {
            let seat_id = attestation["seat_id"]
                .as_str()
                .ok_or_else(|| "roster seat missing".to_owned())?
                .to_owned();
            let signing_key = attestation["signing_key_id"]
                .as_str()
                .ok_or_else(|| "roster signing key missing".to_owned())?
                .to_owned();
            let verification_key = attestation["verification_key"]
                .as_str()
                .ok_or_else(|| "roster verification key missing".to_owned())?
                .to_owned();
            let context_manifest_hash = attestation["context_manifest_hash"]
                .as_str()
                .ok_or_else(|| "roster context missing".to_owned())?
                .to_owned();
            let trusted_seat =
                seat_authority_registry.resolve(tenant_id, protocol_id, &seat_id, body)?;
            let provider_class = attestation["provider_class"]
                .as_str()
                .ok_or_else(|| "roster provider class missing".to_owned())?;
            let controller_did = attestation["controller_did"]
                .as_str()
                .ok_or_else(|| "roster controller DID missing".to_owned())?;
            let attested_independence_proof = attestation["independent_control_proof_hash"]
                .as_str()
                .map(str::to_owned);
            if attestation["tenant_id"] != trusted_seat.tenant_id
                || attestation["protocol_id"] != trusted_seat.protocol_id
                || trusted_seat.seat_did != seat_id
                || trusted_seat.seat_kind != body
                || trusted_seat.provider_class != provider_class
                || trusted_seat.controller_did != controller_did
                || trusted_seat.seat_signing_key_id != signing_key
                || trusted_seat.seat_verification_key != verification_key
                || trusted_seat.context_manifest_hash != context_manifest_hash
                || attestation["valid_from"] != trusted_seat.valid_from
                || attestation["valid_until"] != trusted_seat.valid_until
                || attestation["authority_scope"] != trusted_seat.authority_scope
                || attestation["authority_chain_hash"] != trusted_seat.verified_authority_chain_hash
                || trusted_seat.independent_control_proof_hash != attested_independence_proof
            {
                return Err("seat facts differ from trusted seat authority registry".to_owned());
            }
            verify_seat_attestation(attestation, trusted_seat, &verification_at)?;
            if let Some(existing_class) = controller_provider_classes
                .insert(controller_did.to_owned(), provider_class.to_owned())
            {
                if existing_class != provider_class {
                    return Err(
                        "one controller cannot control seats from distinct provider classes"
                            .to_owned(),
                    );
                }
            }
            if provider_class == "IndependentNonProvider" {
                if attested_independence_proof.is_none()
                    || provider_controller_dids.contains(controller_did)
                    || prohibited_independent_controllers.contains(controller_did)
                {
                    return Err(
                        "independent seat lacks independent control or is provider/Co-PI/Chair controlled"
                            .to_owned(),
                    );
                }
            } else if attested_independence_proof.is_some() {
                return Err("provider seat cannot claim an independent-control proof".to_owned());
            }
            if trusted_signing_authority_by_seat
                .insert(
                    seat_id,
                    (
                        trusted_seat.seat_signing_key_id.clone(),
                        trusted_seat.seat_verification_key.clone(),
                        trusted_seat.context_manifest_hash.clone(),
                        trusted_seat.seat_attestation_hash.clone(),
                    ),
                )
                .is_some()
            {
                return Err("Council and AI-IRB roster seat IDs must be disjoint".to_owned());
            }
        }
        let assignment_pairs: BTreeSet<(String, String)> = assignments
            .iter()
            .filter(|assignment| assignment["seat_kind"] == body)
            .map(|assignment| {
                Ok((
                    assignment["seat_id"]
                        .as_str()
                        .ok_or_else(|| "assignment seat missing".to_owned())?
                        .to_owned(),
                    assignment["context_manifest_hash"]
                        .as_str()
                        .ok_or_else(|| "assignment context missing".to_owned())?
                        .to_owned(),
                ))
            })
            .collect::<Result<_, String>>()?;
        let roster_pairs: BTreeSet<(String, String)> = roster
            .iter()
            .map(|attestation| {
                Ok((
                    attestation["seat_id"]
                        .as_str()
                        .ok_or_else(|| "roster seat missing".to_owned())?
                        .to_owned(),
                    attestation["context_manifest_hash"]
                        .as_str()
                        .ok_or_else(|| "roster context missing".to_owned())?
                        .to_owned(),
                ))
            })
            .collect::<Result<_, String>>()?;
        if assignment_pairs != roster_pairs {
            return Err(format!("{body} assignments do not match roster contexts"));
        }
        body_keys.push(keys);
        body_contexts.push(contexts);
    }
    let reviews = package["review_bundle"]["signed_reviews"]
        .as_array()
        .ok_or_else(|| "signed reviews must be an array".to_owned())?;
    if reviews.len() != 10 {
        return Err("binding requires exactly ten signed peer reviews".to_owned());
    }
    let mut reviewed_assignment_ids = BTreeSet::new();
    for review in reviews {
        if review["disposition"] != "Approve" {
            return Err("binding requires every peer review to Approve".to_owned());
        }
        let target = review["authorization_target_hash"]
            .as_str()
            .ok_or_else(|| "review authorization target missing".to_owned())?;
        if target != expected_authorization_target.as_str() {
            return Err("peer review does not bind the computed authorization target".to_owned());
        }
        all_authorization_targets.insert(target.to_owned());

        let assignment_id = review["assignment_id"]
            .as_str()
            .ok_or_else(|| "review assignment ID missing".to_owned())?;
        let seat_id = assignment_seats
            .get(assignment_id)
            .ok_or_else(|| "review assignment does not resolve".to_owned())?;
        if !reviewed_assignment_ids.insert(assignment_id.to_owned()) {
            return Err("duplicate signed review assignment".to_owned());
        }
        let assignment = assignments
            .iter()
            .find(|assignment| assignment["assignment_id"] == assignment_id)
            .ok_or_else(|| "review assignment body missing".to_owned())?;
        let authority = trusted_signing_authority_by_seat
            .get(seat_id)
            .ok_or_else(|| "review assignment seat has no independently verified key".to_owned())?;
        if assignment["seat_attestation_hash"] != authority.3
            || assignment["context_manifest_hash"] != authority.2
            || review["protocol_version_hash"] != assignment["protocol_version_hash"]
        {
            return Err(
                "peer review does not match its assignment and seat attestation".to_owned(),
            );
        }
        verify_signed_payload(
            "exo.decision_forum.peer_review_signing_payload.v1",
            "PeerReviewV1",
            &peer_review_signing_payload_fixture(review),
            &review["signature"],
            &authority.0,
            &authority.1,
        )?;
    }
    if reviewed_assignment_ids != assignment_seats.keys().cloned().collect() {
        return Err("signed reviews must cover every assignment exactly once".to_owned());
    }
    let review_ids: BTreeSet<String> = reviews
        .iter()
        .map(|review| {
            review["review_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "review ID missing".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let response_hashes: BTreeSet<String> = package["review_bundle"]["author_responses"]
        .as_array()
        .ok_or_else(|| "author responses must be an array".to_owned())?
        .iter()
        .map(|reference| {
            reference["content_hash"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "author response hash missing".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let revision_hashes: BTreeSet<String> = package["review_bundle"]["revision_diffs"]
        .as_array()
        .ok_or_else(|| "revision diffs must be an array".to_owned())?
        .iter()
        .map(|reference| {
            reference["content_hash"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "revision diff hash missing".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let resolutions = package["review_bundle"]["resolution_matrix"]
        .as_array()
        .ok_or_else(|| "resolution matrix must be an array".to_owned())?;
    if resolutions.len() != 10 || response_hashes.len() != 10 || revision_hashes.len() != 10 {
        return Err(
            "binding requires ten unique response, revision, and resolution rows".to_owned(),
        );
    }
    let mut resolved_review_ids = BTreeSet::new();
    let mut resolved_response_hashes = BTreeSet::new();
    let mut resolved_revision_hashes = BTreeSet::new();
    let mut resolution_ids = BTreeSet::new();
    for resolution in resolutions {
        let review_id = resolution["review_id"]
            .as_str()
            .ok_or_else(|| "resolution review ID missing".to_owned())?;
        let review = reviews
            .iter()
            .find(|review| review["review_id"] == review_id)
            .ok_or_else(|| "resolution is orphaned from signed reviews".to_owned())?;
        let response_hash = resolution["author_response_hash"]
            .as_str()
            .ok_or_else(|| "resolution author response hash missing".to_owned())?;
        let revision_hash = resolution["revision_diff_hash"]
            .as_str()
            .ok_or_else(|| "resolution revision hash missing".to_owned())?;
        if resolution["comment_hash"] != review["review_body_hash"]
            || !response_hashes.contains(response_hash)
            || !revision_hashes.contains(revision_hash)
            || !resolved_review_ids.insert(review_id.to_owned())
            || !resolved_response_hashes.insert(response_hash.to_owned())
            || !resolved_revision_hashes.insert(revision_hash.to_owned())
            || !resolution_ids.insert(
                resolution["resolution_id"]
                    .as_str()
                    .ok_or_else(|| "resolution ID missing".to_owned())?
                    .to_owned(),
            )
        {
            return Err(
                "resolution comment/response/revision linkage is not one-to-one".to_owned(),
            );
        }
    }
    if resolved_review_ids != review_ids
        || resolved_response_hashes != response_hashes
        || resolved_revision_hashes != revision_hashes
    {
        return Err("resolution matrix has missing, duplicate, or orphan linkage".to_owned());
    }
    let expected_protocol_version_hash = hash_fixture(
        "exo.decision_forum.protocol_version.v1",
        &package["protocol_identity"],
    );
    let expected_review_bundle_hash = hash_fixture(
        "exo.decision_forum.review_bundle.v1",
        &package["review_bundle"],
    );
    for assignment in assignments {
        let seat_id = assignment["seat_id"]
            .as_str()
            .ok_or_else(|| "assignment seat missing".to_owned())?;
        let authority = trusted_signing_authority_by_seat
            .get(seat_id)
            .ok_or_else(|| "assignment seat is not attested".to_owned())?;
        if assignment["protocol_version_hash"] != expected_protocol_version_hash
            || assignment["seat_attestation_hash"] != authority.3
            || assignment["context_manifest_hash"] != authority.2
        {
            return Err(
                "assignment does not match protocol version and seat attestation".to_owned(),
            );
        }
    }
    for (votes_name, eligible_name, domain, target) in [
        (
            "council_votes",
            "council_eligible_set",
            "exo.decision_forum.council_disposition_signing_payload.v1",
            "CouncilDispositionV1",
        ),
        (
            "ai_irb_votes",
            "ai_irb_eligible_set",
            "exo.decision_forum.ai_irb_disposition_signing_payload.v1",
            "AiIrbDispositionV1",
        ),
    ] {
        let expected_eligible_set_hash = hash_fixture(
            "exo.decision_forum.eligible_set.v1",
            &package["disposition_bundle"][eligible_name],
        );
        for vote in package["disposition_bundle"][votes_name]
            .as_array()
            .ok_or_else(|| format!("{votes_name} must be an array"))?
        {
            let seat_id = vote["seat_id"]
                .as_str()
                .ok_or_else(|| format!("{target} seat missing"))?;
            let authority = trusted_signing_authority_by_seat
                .get(seat_id)
                .ok_or_else(|| format!("{target} seat is not in its roster"))?;
            if vote["protocol_version_hash"] != expected_protocol_version_hash
                || vote["review_bundle_hash"] != expected_review_bundle_hash
                || vote["eligible_set_hash"] != expected_eligible_set_hash
                || vote["seat_attestation_hash"] != authority.3
                || vote["context_manifest_hash"] != authority.2
            {
                return Err(format!(
                    "{target} body does not match roster and package facts"
                ));
            }
            verify_signed_payload(
                domain,
                target,
                &disposition_signing_payload_fixture(vote),
                &vote["signature"],
                &authority.0,
                &authority.1,
            )?;
        }
    }

    let proofs = package["disposition_bundle"]["quorum_proofs"]
        .as_array()
        .ok_or_else(|| "quorum proofs must be an array".to_owned())?;
    if proofs.len() != 2 {
        return Err("binding requires exactly one Council and one AI-IRB quorum proof".to_owned());
    }
    let mut proof_bodies = BTreeSet::new();
    for proof in proofs {
        let body = proof["seat_kind"]
            .as_str()
            .ok_or_else(|| "quorum proof body missing".to_owned())?;
        if !proof_bodies.insert(body.to_owned()) {
            return Err("duplicate quorum proof body".to_owned());
        }
        if proof["result"] != "EligibleUnanimity"
            || proof["eligible_count"] != 5
            || proof["approve_count"] != 5
            || proof["required_count"] != 5
        {
            return Err(format!(
                "{body} quorum proof is not five-of-five eligible unanimity"
            ));
        }
        let providers = string_set(&proof["provider_classes"], "quorum provider classes")?;
        if providers
            != ["AlphabetGoogleGemini", "Anthropic", "OpenAI", "xAI"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        {
            return Err(format!("{body} quorum proof has the wrong provider floor"));
        }
        let proof_evidence =
            independent_evidence_set(&proof["evidence_classes"], "quorum evidence classes")?;
        if proof_evidence != evidence {
            return Err(format!(
                "{body} quorum proof evidence classes differ from the package evidence manifest"
            ));
        }
        let eligible_name = if body == "Council" {
            "council_eligible_set"
        } else if body == "AiIrb" {
            "ai_irb_eligible_set"
        } else {
            return Err("unknown quorum proof body".to_owned());
        };
        let expected_hashes: BTreeSet<String> = package["disposition_bundle"][eligible_name]
            .as_array()
            .ok_or_else(|| "eligible set missing".to_owned())?
            .iter()
            .map(|seat| {
                trusted_signing_authority_by_seat
                    .get(
                        seat.as_str()
                            .ok_or_else(|| "eligible seat missing".to_owned())?,
                    )
                    .map(|authority| authority.3.clone())
                    .ok_or_else(|| "eligible seat is not attested".to_owned())
            })
            .collect::<Result<_, _>>()?;
        if string_set(&proof["eligible_seat_hashes"], "quorum eligible hashes")? != expected_hashes
            || string_set(&proof["approve_seat_hashes"], "quorum approve hashes")?
                != expected_hashes
            || proof["proof_hash"] != quorum_proof_fixture_hash(proof)
        {
            return Err(format!(
                "{body} quorum proof does not match actual roster and votes"
            ));
        }
    }
    if proof_bodies
        != ["AiIrb", "Council"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("quorum proofs do not cover Council and AI-IRB exactly once".to_owned());
    }

    for receipt in package["receipt_manifest"]["preauthorization_lifecycle_receipts"]
        .as_array()
        .ok_or_else(|| "preauthorization receipts must be an array".to_owned())?
    {
        if !receipt["authorized_package_root"].is_null() {
            return Err(
                "in-package lifecycle receipt cannot reference the current package root".to_owned(),
            );
        }
    }
    let prior_version = &package["protocol_identity"]["prior_version_hash"];
    let prior_chain = &package["receipt_manifest"]["prior_execution_receipt_chain"];
    let version = package["protocol_identity"]["version"]
        .as_u64()
        .ok_or_else(|| "protocol version missing".to_owned())?;
    match version {
        1 => {
            if !prior_version.is_null() || !prior_chain.is_null() || verified_predecessor.is_some()
            {
                return Err(
                    "version 1 requires null prior version and null prior execution chain"
                        .to_owned(),
                );
            }
        }
        _ => {
            if prior_version.is_null() || prior_chain.is_null() {
                return Err("version 2 or later requires both predecessor references".to_owned());
            }
            let predecessor = verified_predecessor.ok_or_else(|| {
                "successor package requires a separately verified predecessor chain".to_owned()
            })?;
            verify_prior_execution_reference(prior_chain, predecessor)?;
            if prior_version.as_str() != Some(predecessor.protocol_version_hash.as_str())
                || package["protocol_identity"]["tenant_id"].as_str()
                    != Some(predecessor.tenant_id.as_str())
                || package["protocol_identity"]["protocol_id"].as_str()
                    != Some(predecessor.protocol_id.as_str())
            {
                return Err(
                    "successor prior version/tenant/protocol differs from verified predecessor"
                        .to_owned(),
                );
            }
        }
    }

    let expected_chair_scope = hash_fixture(
        "exo.decision_forum.protocol_envelope.v1",
        &package["protocol_envelope"],
    );
    let chair_did = package["protocol_identity"]["chair_did"]
        .as_str()
        .ok_or_else(|| "Chair DID missing".to_owned())?;
    let chair_authority = &package["protocol_identity"]["chair_authority"];
    let trusted_chair = authority_registry.resolve(
        package["protocol_identity"]["tenant_id"]
            .as_str()
            .ok_or_else(|| "tenant ID missing".to_owned())?,
        package["protocol_identity"]["protocol_id"]
            .as_str()
            .ok_or_else(|| "protocol ID missing".to_owned())?,
        chair_did,
        "ChairInterventionV1",
    )?;
    let authority_references = package["disposition_bundle"]["authority_chain"]
        .as_array()
        .ok_or_else(|| "typed package authority chain must be an array".to_owned())?;
    let publisher_did =
        package["receipt_manifest"]["publication_authorization_receipt"]["publisher_did"]
            .as_str()
            .ok_or_else(|| "publisher DID missing".to_owned())?;
    let trusted_publisher = authority_registry.resolve(
        tenant_id,
        protocol_id,
        publisher_did,
        "PublicationAuthorizationReceiptV1",
    )?;
    let mut expected_authority_references: Vec<Value> = seat_authority_registry
        .entries
        .values()
        .filter(|binding| binding.tenant_id == tenant_id && binding.protocol_id == protocol_id)
        .map(seat_authority_reference)
        .collect();
    expected_authority_references.extend([
        authority_reference(trusted_chair),
        authority_reference(trusted_publisher),
    ]);
    let actual_authority_reference_set: BTreeSet<String> = authority_references
        .iter()
        .map(|reference| {
            serde_json::to_string(reference)
                .map_err(|error| format!("authority reference encoding failed: {error}"))
        })
        .collect::<Result<_, _>>()?;
    let expected_authority_reference_set: BTreeSet<String> = expected_authority_references
        .iter()
        .map(|reference| {
            serde_json::to_string(reference)
                .map_err(|error| format!("trusted authority encoding failed: {error}"))
        })
        .collect::<Result<_, _>>()?;
    if authority_references.len() != 12
        || actual_authority_reference_set.len() != 12
        || actual_authority_reference_set != expected_authority_reference_set
    {
        return Err(
            "typed package authority chain must exactly match ten seats, Chair, and publisher"
                .to_owned(),
        );
    }
    if chair_authority["chair_did"] != chair_did
        || chair_authority["signing_key_id"] != trusted_chair.signing_key_id
        || chair_authority["verification_key"] != trusted_chair.verification_key
        || chair_authority["authority_chain_hash"] != trusted_chair.authority_chain_hash
        || !authority_references.contains(&authority_reference(trusted_chair))
        || chair_authority["signing_key_id"]
            != hash_fixture(
                "exo.decision_forum.verification_key_id.v1",
                &json!({ "verification_key": chair_authority["verification_key"] }),
            )
    {
        return Err("Chair DID or signing-key attestation does not resolve".to_owned());
    }
    for intervention in package["disposition_bundle"]["chair_interventions"]
        .as_array()
        .ok_or_else(|| "Chair interventions must be an array".to_owned())?
    {
        let expected_effect = match intervention["choice"].as_str() {
            Some("Approve") => "EndorsementOnly",
            Some("Reject") => "ScopedHumanOverrideHold",
            Some("Abstain" | "Comment") => "NoAuthorityEffect",
            _ => return Err("Chair intervention choice is unknown".to_owned()),
        };
        if intervention["chair_did"] != chair_did
            || intervention["scope_hash"] != expected_chair_scope
            || intervention["effect"] != expected_effect
            || intervention["authorization_target_hash"] != expected_authorization_target
            || intervention["protocol_version_hash"] != expected_protocol_version_hash
        {
            return Err("Chair choice, effect, scope, or package binding mismatch".to_owned());
        }
        verify_signed_payload(
            "exo.decision_forum.chair_intervention_signing_payload.v1",
            "ChairInterventionV1",
            &chair_intervention_signing_payload_fixture(intervention),
            &intervention["signature"],
            &trusted_chair.signing_key_id,
            &trusted_chair.verification_key,
        )?;
    }

    let genesis = &package["receipt_manifest"]["genesis_adoption_receipt"];
    if !genesis.is_null() {
        if genesis["protocol_id"] != package["protocol_identity"]["protocol_id"]
            || genesis["evidence_bundle_hash"]
                != genesis_evidence_bundle_hash(&genesis["evidence_bundle"])
            || genesis["receipt_root"] != genesis_adoption_receipt_root(genesis)
            || genesis["retroactive_signature_claimed"] != false
        {
            return Err(
                "genesis evidence bundle, root, or prospective-only contract mismatch".to_owned(),
            );
        }
        let expected_prepublication_root = prepublication_fixture_hash(package);
        let forbidden_roots = [
            expected_authorization_target.as_str(),
            expected_prepublication_root.as_str(),
            package["receipt_manifest"]["final_package_root"]
                .as_str()
                .ok_or_else(|| "final package root missing".to_owned())?,
        ];
        let genesis_text = serde_json::to_string(genesis)
            .map_err(|error| format!("genesis serialization failed: {error}"))?;
        if forbidden_roots
            .iter()
            .any(|root| genesis_text.contains(root))
        {
            return Err(
                "genesis evidence contains a current authorization or package root".to_owned(),
            );
        }
    }

    let publication = &package["receipt_manifest"]["publication_authorization_receipt"];
    let publisher = &publication["publisher_authority"];
    if publication["prepublication_root"] != prepublication_fixture_hash(package)
        || publication["publisher_did"] != publisher["publisher_did"]
        || publisher["signing_key_id"] != trusted_publisher.signing_key_id
        || publisher["verification_key"] != trusted_publisher.verification_key
        || publisher["authority_chain_hash"] != trusted_publisher.authority_chain_hash
        || !authority_references.contains(&authority_reference(trusted_publisher))
    {
        return Err(
            "publication authorization body does not match package and authority".to_owned(),
        );
    }
    verify_signed_payload(
        "exo.decision_forum.publication_authorization_receipt.v1",
        "PublicationAuthorizationReceiptV1",
        &publication_authorization_signing_payload_fixture(publication),
        &publication["signature"],
        &trusted_publisher.signing_key_id,
        &trusted_publisher.verification_key,
    )?;
    if all_authorization_targets.len() != 1 {
        return Err(
            "all peer reviews and binding votes must sign one authorization target".to_owned(),
        );
    }
    if !body_keys[0].is_disjoint(&body_keys[1]) || !body_contexts[0].is_disjoint(&body_contexts[1])
    {
        return Err("Council and AI-IRB keys and contexts must be disjoint".to_owned());
    }
    let recomputed_final_root = normalized_final_fixture_hash(package);
    let stored_final_root = package["receipt_manifest"]["final_package_root"]
        .as_str()
        .ok_or_else(|| "stored final package root missing".to_owned())?;
    if recomputed_final_root != stored_final_root {
        return Err(
            "stored final package root differs from normalized authoritative root".to_owned(),
        );
    }
    Ok(VerifiedPackageRoot {
        tenant_id: package["protocol_identity"]["tenant_id"]
            .as_str()
            .ok_or_else(|| "tenant ID missing".to_owned())?
            .to_owned(),
        protocol_id: package["protocol_identity"]["protocol_id"]
            .as_str()
            .ok_or_else(|| "protocol ID missing".to_owned())?
            .to_owned(),
        protocol_version_hash: expected_protocol_version_hash,
        final_package_root: stored_final_root.to_owned(),
    })
}

fn verify_fixture_package(package: &Value) -> Result<VerifiedPackageRoot, String> {
    let authority_registry = fixture_authority_registry();
    let seat_authority_registry = fixture_seat_authority_registry();
    let predecessor = fixture_verified_predecessor(&authority_registry)?;
    assert_binding_semantics(
        package,
        &authority_registry,
        &seat_authority_registry,
        Some(&predecessor),
    )
}

fn assert_semantically_invalid(instance: &Value, case: &str) {
    assert!(
        verify_fixture_package(instance).is_err(),
        "semantic adversarial case passed: {case}"
    );
}

#[test]
fn normative_schema_fixes_package_components_and_deterministic_primitives() {
    let schema_text = read_text("governance/schemas/peer-reviewed-protocol-package-v1.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).expect("normative schema must be valid JSON");

    assert_eq!(
        schema.get("title").and_then(serde_json::Value::as_str),
        Some("PeerReviewedProtocolPackageV1")
    );
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .expect("package schema must declare required components");
    for field in [
        "schema_version",
        "protocol_identity",
        "protocol_document",
        "protocol_envelope",
        "evidence_manifest",
        "review_bundle",
        "disposition_bundle",
        "monitoring_plan",
        "systemic_learning_manifest",
        "commercial_boundary",
        "receipt_manifest",
    ] {
        assert!(
            required.iter().any(|value| value.as_str() == Some(field)),
            "missing {field}"
        );
    }

    let definitions = schema
        .get("$defs")
        .and_then(serde_json::Value::as_object)
        .expect("package schema must declare typed definitions");
    for definition in [
        "Hash256",
        "Did",
        "Timestamp",
        "ProtocolIdentity",
        "ProtocolDocument",
        "ProtocolEnvelope",
        "EvidenceManifest",
        "ReviewBundle",
        "DispositionBundle",
        "MonitoringPlan",
        "SystemicLearningManifest",
        "CommercialBoundary",
        "ReceiptManifest",
        "SeatAttestation",
        "SeatAttestationSignature",
        "CouncilSeatAttestation",
        "AiIrbSeatAttestation",
        "CouncilRoster",
        "AiIrbRoster",
        "ReviewAssignment",
        "PeerReview",
        "PeerReviewSignature",
        "ReviewResolution",
        "DissentRecord",
        "QuorumProof",
        "ChairIntervention",
        "CouncilDisposition",
        "AiIrbDisposition",
        "CouncilDispositionSignature",
        "AiIrbDispositionSignature",
        "AuthorityChainReferenceV1",
        "ChairAuthorityV1",
        "ChairInterventionSignature",
        "PublicationAuthorizationSignature",
        "ProviderClass",
        "EvidenceClass",
        "IndependentEvidenceClass",
        "ResourceCeilings",
        "CommitmentScheme",
        "PublisherAuthorityV1",
        "PublicationAuthorizationReceipt",
        "PreauthorizationLifecycleReceiptV1",
        "PriorExecutionReceiptChainReferenceV1",
        "ExecutionSignerAuthority",
        "ProtocolExecutionReceiptSignature",
        "ProtocolExecutionReceipt",
        "ProtocolExecutionReceiptChainV1",
        "DeterministicArtifactManifestV1",
        "GitObjectId",
        "ProtocolEvent",
        "AarRcaAttestation",
        "CapaRecord",
        "EstopAuthorization",
        "NotificationDeliveryReceipt",
        "ResetAuthorization",
        "PhasePromotion",
        "SystemicLearningRecord",
        "GenesisEvidenceBundleV1",
        "GenesisAdoptionReceipt",
    ] {
        assert!(
            definitions.contains_key(definition),
            "missing definition {definition}"
        );
    }

    assert!(!schema_text.contains("\"type\": \"number\""));
    assert!(!schema_text.contains("HashMap"));
    assert!(!schema_text.contains("HashSet"));
    assert_contains_all(
        &schema_text,
        &[
            "exo.decision_forum.peer_reviewed_protocol_package.v1",
            "canonical-cbor",
            "json-transport-only",
            "caller-supplied",
            "hlc",
        ],
    );

    let validator = compile_schema(&schema);
    let valid = valid_package();
    if let Err(errors) = validator.validate(&valid) {
        panic!(
            "positive package must validate: {}",
            errors
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let authority_registry = fixture_authority_registry();
    let seat_authority_registry = fixture_seat_authority_registry();
    let verified_predecessor = fixture_verified_predecessor(&authority_registry)
        .expect("predecessor P must verify independently");
    let verified_root = assert_binding_semantics(
        &valid,
        &authority_registry,
        &seat_authority_registry,
        Some(&verified_predecessor),
    )
    .expect("positive binding package must produce a verified package root");
    let external_chain_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/ProtocolExecutionReceiptChainV1",
        "$defs": definitions
    });
    let external_chain_validator = compile_schema(&external_chain_schema);
    let allowed_kinds: BTreeSet<&str> = ["ActionExecuted", "ContinuingReview", "AdverseEvent"]
        .into_iter()
        .collect();
    let predecessor_chain = predecessor_execution_chain(&authority_registry);
    assert!(external_chain_validator.is_valid(&predecessor_chain));
    verify_prior_execution_reference(
        &valid["receipt_manifest"]["prior_execution_receipt_chain"],
        &verified_predecessor,
    )
    .expect("version-2 package S must commit exact predecessor chain P");

    let external_chain =
        current_execution_chain(&verified_root, &verified_predecessor, &authority_registry);
    assert!(external_chain_validator.is_valid(&external_chain));
    let current_expectation = ExecutionChainExpectation {
        verified_package_root: &verified_root,
        predecessor_chain_root: &verified_predecessor.chain_root,
        predecessor_terminal_receipt_hash: &verified_predecessor.terminal_receipt_hash,
        predecessor_terminal_sequence: verified_predecessor.terminal_sequence,
        allowed_receipt_kinds: allowed_kinds,
        expected_receipt_count: 3,
    };
    let verified_current =
        verify_execution_chain(&external_chain, &current_expectation, &authority_registry)
            .expect("external current execution chain must verify");
    assert_eq!(verified_predecessor.first_sequence, 1);
    assert_eq!(verified_predecessor.terminal_sequence, 3);
    assert_eq!(verified_current.first_sequence, 4);
    assert_eq!(verified_current.terminal_sequence, 6);
    let successor = successor_package(&valid, &verified_current);
    assert!(validator.is_valid(&successor));
    assert_binding_semantics(
        &successor,
        &authority_registry,
        &seat_authority_registry,
        Some(&verified_current),
    )
    .expect("successor package T must be binding-valid");
    verify_prior_execution_reference(
        &successor["receipt_manifest"]["prior_execution_receipt_chain"],
        &verified_current,
    )
    .expect("P -> S -> C -> T predecessor/successor continuity must verify end-to-end");

    let mut version_one = valid.clone();
    version_one["protocol_identity"]["version"] = json!(1);
    version_one["protocol_identity"]["prior_version_hash"] = Value::Null;
    version_one["receipt_manifest"]["prior_execution_receipt_chain"] = Value::Null;
    version_one = bind_package(version_one);
    assert!(validator.is_valid(&version_one));
    assert_binding_semantics(
        &version_one,
        &authority_registry,
        &seat_authority_registry,
        None,
    )
    .expect("version 1 with both predecessor references null must verify");

    let mut version_two_both_null = valid.clone();
    version_two_both_null["protocol_identity"]["prior_version_hash"] = Value::Null;
    version_two_both_null["receipt_manifest"]["prior_execution_receipt_chain"] = Value::Null;
    version_two_both_null = bind_package(version_two_both_null);
    assert_invalid(
        &validator,
        &version_two_both_null,
        "version 2 with both predecessor references null",
    );
    assert!(
        assert_binding_semantics(
            &version_two_both_null,
            &authority_registry,
            &seat_authority_registry,
            None,
        )
        .is_err()
    );

    let mut version_one_nonnull = version_one.clone();
    version_one_nonnull["protocol_identity"]["prior_version_hash"] =
        json!(verified_predecessor.protocol_version_hash);
    version_one_nonnull["receipt_manifest"]["prior_execution_receipt_chain"] =
        prior_execution_chain_reference(&verified_predecessor);
    version_one_nonnull = bind_package(version_one_nonnull);
    assert_invalid(
        &validator,
        &version_one_nonnull,
        "version 1 with non-null predecessor references",
    );
    assert!(
        assert_binding_semantics(
            &version_one_nonnull,
            &authority_registry,
            &seat_authority_registry,
            Some(&verified_predecessor),
        )
        .is_err()
    );

    for (case, prior_version_value, prior_chain_value) in [
        (
            "version 2 prior-version only",
            json!(verified_predecessor.protocol_version_hash),
            Value::Null,
        ),
        (
            "version 2 prior-chain only",
            Value::Null,
            prior_execution_chain_reference(&verified_predecessor),
        ),
    ] {
        let mut half_null = valid.clone();
        half_null["protocol_identity"]["prior_version_hash"] = prior_version_value;
        half_null["receipt_manifest"]["prior_execution_receipt_chain"] = prior_chain_value;
        half_null = bind_package(half_null);
        assert_invalid(&validator, &half_null, case);
        assert!(
            assert_binding_semantics(
                &half_null,
                &authority_registry,
                &seat_authority_registry,
                Some(&verified_predecessor),
            )
            .is_err(),
            "{case} passed semantic verification",
        );
    }

    let mut draft_binding = valid.clone();
    draft_binding["protocol_identity"]["lifecycle_state"] = json!("Draft");
    assert_invalid(&validator, &draft_binding, "binding package in Draft state");
    assert_semantically_invalid(&draft_binding, "binding package lifecycle is not Approved");

    let mut executed_binding = valid.clone();
    executed_binding["protocol_identity"]["lifecycle_state"] = json!("Executed");
    assert_invalid(
        &validator,
        &executed_binding,
        "binding package in Executed state",
    );
    assert_semantically_invalid(
        &executed_binding,
        "binding package must be exactly Approved",
    );

    let mut dissent_mismatch = valid.clone();
    dissent_mismatch["disposition_bundle"]["dissents"] = json!([{
        "dissent_id": "00000000-0000-4000-8000-000000000099",
        "seat_id": "did:exo:openai",
        "context": "Authorization",
        "body_hash": hash256(),
        "effect": "ChairAlertAndContinuingReview",
        "recorded_at": timestamp(0),
        "chair_alert_receipt_hash": hash256(),
        "signature_hash": hash256()
    }]);
    assert_invalid(
        &validator,
        &dissent_mismatch,
        "authorization dissent effect mismatch",
    );

    let mut chair_mismatch = valid.clone();
    chair_mismatch["disposition_bundle"]["chair_interventions"][0]["effect"] =
        json!("ScopedHumanOverrideHold");
    assert_invalid(&validator, &chair_mismatch, "Chair approve/hold mismatch");
    assert_semantically_invalid(&chair_mismatch, "Chair effect mutation");

    let mut chair_body_mutation = valid.clone();
    chair_body_mutation["disposition_bundle"]["chair_interventions"][0]["comment_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&chair_body_mutation, "Chair signed body mutation");

    let mut chair_key_mutation = valid.clone();
    chair_key_mutation["disposition_bundle"]["chair_interventions"][0]["signature"]["signing_key_id"] =
        json!(fixture_key_material(11).0);
    assert_semantically_invalid(&chair_key_mutation, "Chair signing key mutation");

    let mut chair_chain_mismatch = valid.clone();
    chair_chain_mismatch["protocol_identity"]["chair_authority"]["authority_chain_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &chair_chain_mismatch,
        "Chair authority-chain hash differs from trusted registry and typed package reference",
    );

    let mut typed_chair_reference_mismatch = valid.clone();
    let typed_chair_reference =
        typed_chair_reference_mismatch["disposition_bundle"]["authority_chain"]
            .as_array_mut()
            .expect("fixture authority chain")
            .iter_mut()
            .find(|reference| {
                reference["binding_kind"] == "NonSeatAuthority"
                    && reference["actor_did"] == "did:exo:bob-stewart"
                    && reference["scope"] == "ChairInterventionV1"
            })
            .expect("fixture typed Chair authority reference");
    typed_chair_reference["authority_chain_hash"] = json!(hash_with('f'));
    assert_semantically_invalid(
        &typed_chair_reference_mismatch,
        "typed package Chair authority reference mismatch",
    );

    let mut chair_signature_mutation = valid.clone();
    chair_signature_mutation["disposition_bundle"]["chair_interventions"][0]["signature"]["signature"] =
        json!(repeated_hex('f', 128));
    assert_semantically_invalid(&chair_signature_mutation, "Chair signature mutation");

    let mut chair_scope_mutation = valid.clone();
    chair_scope_mutation["disposition_bundle"]["chair_interventions"][0]["scope_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&chair_scope_mutation, "Chair scope mutation");

    let mut wrong_body_vote = valid.clone();
    wrong_body_vote["disposition_bundle"]["council_votes"][0] =
        valid["disposition_bundle"]["ai_irb_votes"][0].clone();
    assert_invalid(&validator, &wrong_body_vote, "AI-IRB vote in Council array");

    let mut excess_seat = valid.clone();
    excess_seat["review_bundle"]["council_seat_attestations"]
        .as_object_mut()
        .expect("Council roster is an object")
        .insert(
            "extra".to_owned(),
            valid["review_bundle"]["council_seat_attestations"]["openai"].clone(),
        );
    assert_invalid(&validator, &excess_seat, "sixth Council seat");

    let mut missing_provider = valid.clone();
    missing_provider["review_bundle"]["council_seat_attestations"]
        .as_object_mut()
        .expect("Council roster is an object")
        .remove("openai");
    assert_invalid(
        &validator,
        &missing_provider,
        "missing OpenAI provider seat",
    );

    let mut invalid_provider = valid.clone();
    invalid_provider["review_bundle"]["council_seat_attestations"]["openai"]["provider_class"] =
        json!("UnknownProvider");
    assert_invalid(&validator, &invalid_provider, "unrecognized provider class");

    let mut wrong_named_provider = valid.clone();
    wrong_named_provider["review_bundle"]["council_seat_attestations"]["openai"]["provider_class"] =
        json!("Anthropic");
    assert_invalid(
        &validator,
        &wrong_named_provider,
        "wrong provider in fixed roster slot",
    );

    let mut provider_controller_mismatch = valid.clone();
    provider_controller_mismatch["review_bundle"]["council_seat_attestations"]["openai"]["controller_did"] =
        valid["review_bundle"]["council_seat_attestations"]["anthropic"]["controller_did"].clone();
    assert_semantically_invalid(
        &provider_controller_mismatch,
        "OpenAI seat laundered through Anthropic controller",
    );

    let mut shared_controller_across_provider_classes = valid.clone();
    shared_controller_across_provider_classes["review_bundle"]["council_seat_attestations"]["anthropic"]
        ["controller_did"] =
        valid["review_bundle"]["council_seat_attestations"]["openai"]["controller_did"].clone();
    assert_semantically_invalid(
        &shared_controller_across_provider_classes,
        "one controller reused across distinct provider classes",
    );

    let mut provider_controls_independent = valid.clone();
    provider_controls_independent["review_bundle"]["council_seat_attestations"]["independent_non_provider"]
        ["controller_did"] =
        valid["review_bundle"]["council_seat_attestations"]["openai"]["controller_did"].clone();
    assert_semantically_invalid(
        &provider_controls_independent,
        "provider controls independent Council seat",
    );

    let mut chair_controls_independent = valid.clone();
    chair_controls_independent["review_bundle"]["ai_irb_seat_attestations"]["independent_non_provider"]
        ["controller_did"] = json!("did:exo:bob-stewart");
    assert_semantically_invalid(
        &chair_controls_independent,
        "Chair or Co-PI controls independent AI-IRB seat",
    );

    let mut missing_independent_control_proof = valid.clone();
    missing_independent_control_proof["review_bundle"]["council_seat_attestations"]["independent_non_provider"]
        ["independent_control_proof_hash"] = Value::Null;
    assert_invalid(
        &validator,
        &missing_independent_control_proof,
        "independent seat lacks independent-control proof",
    );
    assert_semantically_invalid(
        &missing_independent_control_proof,
        "independent seat lacks trusted independent-control proof",
    );

    let mut one_seat_key_substitution = valid.clone();
    let substituted_attestation =
        &mut one_seat_key_substitution["review_bundle"]["council_seat_attestations"]["openai"];
    let (substituted_key_id, substituted_verification_key) = fixture_key_material(31);
    substituted_attestation["signing_key_id"] = json!(substituted_key_id);
    substituted_attestation["verification_key"] = json!(substituted_verification_key);
    substituted_attestation["signature"] = sign_payload(
        "exo.decision_forum.seat_attestation_signing_payload.v1",
        "SeatAttestationV1",
        &seat_attestation_signing_payload_fixture(substituted_attestation),
        fixture_controller_seed("did:exo:openai"),
    );
    assert_semantically_invalid(
        &one_seat_key_substitution,
        "one seat key substitution remains denied after a valid controller re-sign",
    );

    let mut controller_signature_mutation = valid.clone();
    controller_signature_mutation["review_bundle"]["council_seat_attestations"]["openai"]["signature"]
        ["signature"] = json!(repeated_hex('f', 128));
    assert_semantically_invalid(
        &controller_signature_mutation,
        "seat controller attestation signature mutation",
    );

    let mut seat_authority_chain_mismatch = valid.clone();
    let openai_authority_reference =
        seat_authority_chain_mismatch["disposition_bundle"]["authority_chain"]
            .as_array_mut()
            .expect("fixture authority chain")
            .iter_mut()
            .find(|reference| reference["actor_did"] == "did:exo:openai")
            .expect("fixture OpenAI authority reference");
    openai_authority_reference["authority_chain_hash"] = json!(hash_with('f'));
    assert_semantically_invalid(
        &seat_authority_chain_mismatch,
        "seat authority-chain reference differs from trusted registry",
    );

    let trusted_openai = seat_authority_registry
        .resolve("tenant-1", "DF-PROTOCOL-001", "did:exo:openai", "Council")
        .expect("fixture OpenAI authority")
        .clone();
    for (case, valid_from, valid_until) in [
        ("expired seat authority", timestamp(0), timestamp(0)),
        ("not-yet-valid seat authority", timestamp(2), timestamp(3)),
    ] {
        let mut invalid_window = trusted_openai.clone();
        invalid_window.valid_from = valid_from;
        invalid_window.valid_until = valid_until;
        let attestation = seat_attestation_from_binding(
            &invalid_window,
            fixture_controller_seed(&invalid_window.seat_did),
        );
        invalid_window.seat_attestation_hash =
            hash_fixture("exo.decision_forum.seat_attestation.v1", &attestation);
        assert!(
            verify_seat_attestation(&attestation, &invalid_window, &timestamp(1)).is_err(),
            "{case} passed trusted HLC validity verification",
        );
    }

    let trusted_registry_snapshot = seat_authority_registry.clone();
    let fully_resigned_attack = fully_resign_with_untrusted_seat_keys(&valid);
    assert_eq!(
        &seat_authority_registry.entries, &trusted_registry_snapshot.entries,
        "attacker fixture must not mutate or rebuild the trusted seat registry",
    );
    assert!(validator.is_valid(&fully_resigned_attack));
    assert_ne!(
        fully_resigned_attack["receipt_manifest"]["final_package_root"],
        valid["receipt_manifest"]["final_package_root"],
    );
    let changed_seat_keys = fixture_seat_rows()
        .into_iter()
        .filter(|(seat_did, seat_kind, _, _, _, _, _, _, _)| {
            let roster_name = if *seat_kind == "Council" {
                "council_seat_attestations"
            } else {
                "ai_irb_seat_attestations"
            };
            let attacked_attestation = fully_resigned_attack["review_bundle"][roster_name]
                .as_object()
                .expect("fixture attacked roster")
                .values()
                .find(|attestation| attestation["seat_id"] == *seat_did)
                .expect("fixture attacked seat");
            let trusted = seat_authority_registry
                .resolve("tenant-1", "DF-PROTOCOL-001", seat_did, seat_kind)
                .expect("fixture trusted seat");
            attacked_attestation["signing_key_id"] != trusted.seat_signing_key_id
                && attacked_attestation["verification_key"] != trusted.seat_verification_key
        })
        .count();
    assert_eq!(changed_seat_keys, 10);
    assert!(
        assert_binding_semantics(
            &fully_resigned_attack,
            &authority_registry,
            &seat_authority_registry,
            Some(&verified_predecessor),
        )
        .is_err(),
        "fully re-signed ten-seat attacker graph passed unchanged trusted registry",
    );

    let mut invalid_evidence = valid.clone();
    invalid_evidence["evidence_manifest"]["independent_evidence_classes"][0] =
        json!("ProviderProse");
    assert_invalid(&validator, &invalid_evidence, "unrecognized evidence class");

    let mut provider_judgment_floor = valid.clone();
    provider_judgment_floor["evidence_manifest"]["independent_evidence_classes"] =
        json!(["ProviderModelJudgment", "IndependentNonProviderEvidence"]);
    provider_judgment_floor = bind_package(provider_judgment_floor);
    assert_ne!(
        provider_judgment_floor["receipt_manifest"]["final_package_root"],
        valid["receipt_manifest"]["final_package_root"],
        "adversarial evidence substitution must recompute the final root",
    );
    assert_eq!(
        provider_judgment_floor["receipt_manifest"]["final_package_root"],
        normalized_final_fixture_hash(&provider_judgment_floor),
        "adversarial fixture must be fully rebound and rehashed before rejection",
    );
    for proof in provider_judgment_floor["disposition_bundle"]["quorum_proofs"]
        .as_array()
        .expect("fixture quorum proofs")
    {
        assert_eq!(
            proof["evidence_classes"],
            json!(["ProviderModelJudgment", "IndependentNonProviderEvidence"]),
        );
        assert_eq!(proof["proof_hash"], quorum_proof_fixture_hash(proof));
    }
    assert_invalid(
        &validator,
        &provider_judgment_floor,
        "ProviderModelJudgment cannot satisfy the independent evidence floor after full rebind and rehash",
    );
    let provider_judgment_result = assert_binding_semantics(
        &provider_judgment_floor,
        &authority_registry,
        &seat_authority_registry,
        Some(&verified_predecessor),
    );
    assert!(
        provider_judgment_result.is_err(),
        "ProviderModelJudgment plus IndependentNonProviderEvidence produced VerifiedPackageRoot",
    );
    let impossible_execution_chain = provider_judgment_result
        .as_ref()
        .map(|root| current_execution_chain(root, &verified_predecessor, &authority_registry));
    assert!(
        impossible_execution_chain.is_err(),
        "ProviderModelJudgment independent-floor substitution authorized execution",
    );

    let mut missing_non_provider_evidence = valid.clone();
    missing_non_provider_evidence["evidence_manifest"]["independent_evidence_classes"] =
        json!(["DeterministicTest", "ExternalAudit"]);
    assert_invalid(
        &validator,
        &missing_non_provider_evidence,
        "missing IndependentNonProviderEvidence",
    );

    let mut missing_second_evidence = valid.clone();
    missing_second_evidence["evidence_manifest"]["independent_evidence_classes"] =
        json!(["IndependentNonProviderEvidence"]);
    assert_invalid(
        &validator,
        &missing_second_evidence,
        "missing second evidence class",
    );

    let mut non_approve = valid.clone();
    non_approve["disposition_bundle"]["council_votes"][0]["choice"] = json!("Reject");
    assert_invalid(&validator, &non_approve, "non-Approve binding vote");

    let mut duplicate_vote_seat = valid.clone();
    duplicate_vote_seat["disposition_bundle"]["council_votes"][1]["seat_id"] =
        json!("did:exo:openai");
    assert_semantically_invalid(&duplicate_vote_seat, "duplicate vote seat ID");

    let mut eligible_vote_mismatch = valid.clone();
    eligible_vote_mismatch["disposition_bundle"]["council_eligible_set"][0] =
        json!("did:exo:replacement");
    assert_semantically_invalid(&eligible_vote_mismatch, "eligible/vote/roster mismatch");

    let mut reused_key_and_context = valid.clone();
    let council_key =
        valid["review_bundle"]["council_seat_attestations"]["openai"]["signing_key_id"].clone();
    let council_verification_key =
        valid["review_bundle"]["council_seat_attestations"]["openai"]["verification_key"].clone();
    let council_context =
        valid["review_bundle"]["council_seat_attestations"]["openai"]["context_manifest_hash"]
            .clone();
    reused_key_and_context["review_bundle"]["ai_irb_seat_attestations"]["openai"]["signing_key_id"] =
        council_key;
    reused_key_and_context["review_bundle"]["ai_irb_seat_attestations"]["openai"]["verification_key"] =
        council_verification_key;
    reused_key_and_context["review_bundle"]["ai_irb_seat_attestations"]["openai"]["context_manifest_hash"] =
        council_context;
    assert_semantically_invalid(
        &reused_key_and_context,
        "Council/AI-IRB key and context reuse",
    );

    let mut assignment_mismatch = valid.clone();
    assignment_mismatch["review_bundle"]["assignments"][0]["seat_id"] =
        json!("did:exo:replacement");
    assert_semantically_invalid(&assignment_mismatch, "body assignment mismatch");

    let mut unresolved_review_assignment = valid.clone();
    unresolved_review_assignment["review_bundle"]["signed_reviews"][0]["assignment_id"] =
        json!("00000000-0000-4000-8000-000000000099");
    assert_semantically_invalid(
        &unresolved_review_assignment,
        "peer review assignment does not resolve",
    );

    let mut wrong_review_signing_key = valid.clone();
    wrong_review_signing_key["review_bundle"]["signed_reviews"][0]["signature"]["signing_key_id"] =
        json!(hash_with('2'));
    assert_semantically_invalid(
        &wrong_review_signing_key,
        "peer-review signature key does not match assignment",
    );

    let mut changed_review_signed_payload = valid.clone();
    changed_review_signed_payload["review_bundle"]["signed_reviews"][0]["signature"]["signed_payload_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &changed_review_signed_payload,
        "peer-review signature does not bind canonical review body",
    );

    let mut missing_assignment = valid.clone();
    missing_assignment["review_bundle"]["assignments"]
        .as_array_mut()
        .expect("fixture assignments")
        .pop();
    assert_invalid(&validator, &missing_assignment, "missing tenth assignment");

    let mut duplicate_assignment = valid.clone();
    duplicate_assignment["review_bundle"]["assignments"][1] =
        valid["review_bundle"]["assignments"][0].clone();
    assert_semantically_invalid(&duplicate_assignment, "duplicate assignment");

    let mut wrong_council_role = valid.clone();
    wrong_council_role["review_bundle"]["assignments"][1]["review_role"] = json!("Governance");
    assert_semantically_invalid(&wrong_council_role, "duplicate Council role");

    let mut wrong_ai_irb_role = valid.clone();
    wrong_ai_irb_role["review_bundle"]["assignments"][5]["review_role"] = json!("Governance");
    assert_semantically_invalid(&wrong_ai_irb_role, "wrong AI-IRB review role");

    let mut missing_review = valid.clone();
    missing_review["review_bundle"]["signed_reviews"]
        .as_array_mut()
        .expect("fixture reviews")
        .pop();
    assert_invalid(&validator, &missing_review, "missing tenth signed review");

    let mut duplicate_review = valid.clone();
    duplicate_review["review_bundle"]["signed_reviews"][1] =
        valid["review_bundle"]["signed_reviews"][0].clone();
    assert_semantically_invalid(&duplicate_review, "duplicate review assignment");

    let mut wrong_review_body = valid.clone();
    wrong_review_body["review_bundle"]["signed_reviews"][0]["review_body_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&wrong_review_body, "review body changed after signing");

    let mut missing_resolution = valid.clone();
    missing_resolution["review_bundle"]["resolution_matrix"]
        .as_array_mut()
        .expect("fixture resolutions")
        .pop();
    assert_invalid(
        &validator,
        &missing_resolution,
        "missing review resolution row",
    );
    assert_semantically_invalid(&missing_resolution, "missing review response coverage");

    let mut duplicate_resolution = valid.clone();
    duplicate_resolution["review_bundle"]["resolution_matrix"][1] =
        valid["review_bundle"]["resolution_matrix"][0].clone();
    assert_semantically_invalid(&duplicate_resolution, "duplicate review resolution row");

    let mut orphan_resolution = valid.clone();
    orphan_resolution["review_bundle"]["resolution_matrix"][0]["review_id"] =
        json!("00000000-0000-4000-8000-000000000099");
    assert_semantically_invalid(&orphan_resolution, "orphan review resolution row");

    let mut wrong_resolution_comment = valid.clone();
    wrong_resolution_comment["review_bundle"]["resolution_matrix"][0]["comment_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &wrong_resolution_comment,
        "review resolution comment linkage mutation",
    );

    let mut wrong_resolution_response = valid.clone();
    wrong_resolution_response["review_bundle"]["resolution_matrix"][0]["author_response_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &wrong_resolution_response,
        "review resolution response linkage mutation",
    );

    let mut wrong_resolution_revision = valid.clone();
    wrong_resolution_revision["review_bundle"]["resolution_matrix"][0]["revision_diff_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &wrong_resolution_revision,
        "review resolution revision linkage mutation",
    );

    let mut wrong_vote_key = valid.clone();
    wrong_vote_key["disposition_bundle"]["council_votes"][0]["signature"]["verification_key"] =
        json!(fixture_key_material(2).1);
    assert_semantically_invalid(&wrong_vote_key, "vote verification key mismatch");

    let mut wrong_vote_context = valid.clone();
    wrong_vote_context["disposition_bundle"]["ai_irb_votes"][0]["context_manifest_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&wrong_vote_context, "vote context mismatch");

    let mut changed_vote_body = valid.clone();
    changed_vote_body["disposition_bundle"]["council_votes"][0]["signed_at"] = timestamp(2);
    assert_semantically_invalid(&changed_vote_body, "vote body changed after signing");

    let mut duplicate_quorum = valid.clone();
    duplicate_quorum["disposition_bundle"]["quorum_proofs"][1] =
        valid["disposition_bundle"]["quorum_proofs"][0].clone();
    assert_semantically_invalid(&duplicate_quorum, "duplicate Council quorum proof");

    let mut nonunanimous_quorum = valid.clone();
    nonunanimous_quorum["disposition_bundle"]["quorum_proofs"][0]["approve_count"] = json!(4);
    assert_semantically_invalid(&nonunanimous_quorum, "counterfeit nonunanimous proof");

    let mut quorum_floor_mismatch = valid.clone();
    quorum_floor_mismatch["disposition_bundle"]["quorum_proofs"][0]["provider_classes"][0] =
        json!("IndependentNonProvider");
    let forged_provider_proof_hash =
        quorum_proof_fixture_hash(&quorum_floor_mismatch["disposition_bundle"]["quorum_proofs"][0]);
    quorum_floor_mismatch["disposition_bundle"]["quorum_proofs"][0]["proof_hash"] =
        json!(forged_provider_proof_hash);
    assert_semantically_invalid(&quorum_floor_mismatch, "quorum provider-floor mismatch");

    let mut quorum_evidence_substitution = valid.clone();
    quorum_evidence_substitution["disposition_bundle"]["quorum_proofs"][0]["evidence_classes"] =
        json!(["ExternalAudit", "IndependentNonProviderEvidence"]);
    let forged_evidence_proof_hash = quorum_proof_fixture_hash(
        &quorum_evidence_substitution["disposition_bundle"]["quorum_proofs"][0],
    );
    quorum_evidence_substitution["disposition_bundle"]["quorum_proofs"][0]["proof_hash"] =
        json!(forged_evidence_proof_hash);
    assert_semantically_invalid(
        &quorum_evidence_substitution,
        "quorum evidence substitution cannot pass by rehashing",
    );

    let mut quorum_body_mismatch = valid.clone();
    quorum_body_mismatch["disposition_bundle"]["quorum_proofs"][0]["eligible_seat_hashes"][0] =
        json!(hash_with('f'));
    assert_semantically_invalid(&quorum_body_mismatch, "quorum roster mismatch");

    let mut changed_publication_body = valid.clone();
    changed_publication_body["receipt_manifest"]["publication_authorization_receipt"]["renderer_manifest_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(
        &changed_publication_body,
        "publication authorization body changed after signing",
    );

    let mut changed_publication_signature = valid.clone();
    changed_publication_signature["receipt_manifest"]["publication_authorization_receipt"]["signature"]
        ["signature"] = json!(repeated_hex('f', 128));
    assert_semantically_invalid(
        &changed_publication_signature,
        "publication authorization signature forged",
    );

    let mut current_root_in_package = valid.clone();
    let current_root = current_root_in_package["receipt_manifest"]["final_package_root"].clone();
    current_root_in_package["receipt_manifest"]["preauthorization_lifecycle_receipts"][0]["authorized_package_root"] =
        current_root;
    assert_semantically_invalid(
        &current_root_in_package,
        "current package root appears in an in-package receipt",
    );

    let mut forged_stored_root = valid.clone();
    forged_stored_root["receipt_manifest"]["final_package_root"] = json!(hash_with('f'));
    assert!(
        validator.is_valid(&forged_stored_root),
        "stored-root forgery must remain transport-schema-valid for semantic regression proof",
    );
    assert_semantically_invalid(
        &forged_stored_root,
        "stored final root differs from recomputed normalized root",
    );

    let mut noncanonical_uuid = valid.clone();
    noncanonical_uuid["review_bundle"]["assignments"][0]["assignment_id"] =
        json!("00000000-0000-4000-8000-00000000000A");
    assert_invalid(&validator, &noncanonical_uuid, "uppercase UUID");

    let mut genesis_bundle_mutation = valid.clone();
    genesis_bundle_mutation["receipt_manifest"]["genesis_adoption_receipt"]["evidence_bundle"]["chronology_manifest_hash"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&genesis_bundle_mutation, "genesis evidence bundle mutation");

    let mut genesis_root_mutation = valid.clone();
    genesis_root_mutation["receipt_manifest"]["genesis_adoption_receipt"]["receipt_root"] =
        json!(hash_with('f'));
    assert_semantically_invalid(&genesis_root_mutation, "genesis receipt-root mutation");

    for (case, root) in [
        (
            "genesis current authorization-target injection",
            authorization_target_fixture_hash(&valid),
        ),
        (
            "genesis current prepublication-root injection",
            prepublication_fixture_hash(&valid),
        ),
        (
            "genesis current final-root injection",
            valid["receipt_manifest"]["final_package_root"]
                .as_str()
                .expect("fixture final root")
                .to_owned(),
        ),
    ] {
        let mut injected = valid.clone();
        injected["receipt_manifest"]["genesis_adoption_receipt"]["evidence_bundle"]["historical_review_evidence_hash"] =
            json!(root);
        let bundle_hash = genesis_evidence_bundle_hash(
            &injected["receipt_manifest"]["genesis_adoption_receipt"]["evidence_bundle"],
        );
        injected["receipt_manifest"]["genesis_adoption_receipt"]["evidence_bundle_hash"] =
            json!(bundle_hash);
        let receipt_root = genesis_adoption_receipt_root(
            &injected["receipt_manifest"]["genesis_adoption_receipt"],
        );
        injected["receipt_manifest"]["genesis_adoption_receipt"]["receipt_root"] =
            json!(receipt_root);
        assert_semantically_invalid(&injected, case);
    }

    let mut wrong_git_digest = valid;
    wrong_git_digest["receipt_manifest"]["genesis_adoption_receipt"]["evidence_bundle"]["historical_commit_ids"]
        [0]["digest"] = json!(hash256());
    assert_invalid(
        &validator,
        &wrong_git_digest,
        "SHA-1 Git ID encoded as Hash256",
    );
}

#[test]
fn commitment_construction_is_acyclic_and_mutation_complete() {
    let package = valid_package();
    let authority_registry = fixture_authority_registry();
    let seat_authority_registry = fixture_seat_authority_registry();
    let verified_predecessor = fixture_verified_predecessor(&authority_registry)
        .expect("predecessor chain must verify independently");
    let verified_root = assert_binding_semantics(
        &package,
        &authority_registry,
        &seat_authority_registry,
        Some(&verified_predecessor),
    )
    .expect("positive package must produce an opaque verified root");
    let authorization = authorization_target_fixture_hash(&package);
    let prepublication = prepublication_fixture_hash(&package);
    let final_root = normalized_final_fixture_hash(&package);
    assert_eq!(
        package["receipt_manifest"]["final_package_root"],
        final_root
    );
    for body in ["council_votes", "ai_irb_votes"] {
        for vote in package["disposition_bundle"][body]
            .as_array()
            .expect("fixture votes must be arrays")
        {
            assert_eq!(vote["authorization_target_hash"], authorization);
        }
    }
    assert_eq!(
        package["receipt_manifest"]["publication_authorization_receipt"]["prepublication_root"],
        prepublication,
    );

    for (case, pointer) in [
        ("protocol document", "/protocol_document/purpose"),
        ("envelope", "/protocol_envelope/permitted_actions/0"),
        ("evidence", "/evidence_manifest/items/0/content_hash"),
        (
            "assignment",
            "/review_bundle/assignments/0/blind_commitment",
        ),
        (
            "review body",
            "/review_bundle/signed_reviews/0/review_body_hash",
        ),
        (
            "review target key",
            "/review_bundle/signed_reviews/0/signature/signing_key_id",
        ),
        ("monitoring", "/monitoring_plan/success_stop_condition"),
        (
            "commercial boundary",
            "/commercial_boundary/permitted_use_hash",
        ),
        (
            "preauthorization lifecycle receipt",
            "/receipt_manifest/preauthorization_lifecycle_receipts/0/receipt_hash",
        ),
        (
            "prior execution chain commitment",
            "/receipt_manifest/prior_execution_receipt_chain/chain_root",
        ),
        (
            "genesis adoption receipt",
            "/receipt_manifest/genesis_adoption_receipt/evidence_bundle/chronology_manifest_hash",
        ),
        (
            "prior version link",
            "/protocol_identity/prior_version_hash",
        ),
    ] {
        let mut mutated = package.clone();
        *mutated
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("fixture path {pointer}")) = json!(hash_with('f'));
        assert_ne!(
            authorization_target_fixture_hash(&mutated),
            authorization,
            "{case} mutation did not change authorization target",
        );
    }

    let mut changed_vote = package.clone();
    changed_vote["disposition_bundle"]["council_votes"][0]["choice"] = json!("Reject");
    assert_eq!(
        authorization_target_fixture_hash(&changed_vote),
        authorization
    );
    assert_ne!(normalized_final_fixture_hash(&changed_vote), final_root);

    let mut changed_review_signature = package.clone();
    changed_review_signature["review_bundle"]["signed_reviews"][0]["signature"]["signature"] =
        json!(repeated_hex('f', 128));
    assert_eq!(
        authorization_target_fixture_hash(&changed_review_signature),
        authorization,
    );
    assert_ne!(
        normalized_final_fixture_hash(&changed_review_signature),
        final_root,
    );

    let mut changed_receipt = package.clone();
    changed_receipt["receipt_manifest"]["preauthorization_lifecycle_receipts"][0]["receipt_hash"] =
        json!(hash_with('f'));
    assert_ne!(
        authorization_target_fixture_hash(&changed_receipt),
        authorization
    );
    assert_ne!(normalized_final_fixture_hash(&changed_receipt), final_root);

    let mut changed_publication_authorization = package.clone();
    changed_publication_authorization["receipt_manifest"]["publication_authorization_receipt"]["renderer_manifest_hash"] =
        json!(hash_with('f'));
    assert_eq!(
        prepublication_fixture_hash(&changed_publication_authorization),
        prepublication,
    );
    assert_ne!(
        normalized_final_fixture_hash(&changed_publication_authorization),
        final_root,
    );
    let mut changed_publication_signature = package.clone();
    changed_publication_signature["receipt_manifest"]["publication_authorization_receipt"]["signature"]
        ["signature"] = json!(repeated_hex('f', 128));
    assert_ne!(
        normalized_final_fixture_hash(&changed_publication_signature),
        final_root
    );
    assert!(verify_fixture_package(&changed_publication_signature).is_err());

    for review_index in 0..10 {
        for (field, value, changes_authorization) in [
            ("review_body_hash", json!(hash_with('f')), true),
            ("authorization_target_hash", json!(hash_with('f')), false),
        ] {
            let mut mutated = package.clone();
            mutated["review_bundle"]["signed_reviews"][review_index][field] = value;
            if changes_authorization {
                assert_ne!(
                    authorization_target_fixture_hash(&mutated),
                    authorization,
                    "review {review_index} body mutation escaped authorization commitment",
                );
            }
            assert!(
                normalized_final_fixture_hash(&mutated) != final_root
                    || verify_fixture_package(&mutated).is_err(),
                "review {review_index} {field} mutation neither changed commitment nor failed verification",
            );
        }
        for (field, value) in [
            ("signing_key_id", json!(hash_with('f'))),
            ("signature", json!(repeated_hex('f', 128))),
        ] {
            let mut mutated = package.clone();
            mutated["review_bundle"]["signed_reviews"][review_index]["signature"][field] = value;
            assert!(
                normalized_final_fixture_hash(&mutated) != final_root
                    || verify_fixture_package(&mutated).is_err(),
                "review {review_index} signature {field} mutation escaped verification",
            );
        }
    }

    for votes_name in ["council_votes", "ai_irb_votes"] {
        for vote_index in 0..5 {
            for (pointer_suffix, value) in [
                ("choice", json!("Reject")),
                ("context_manifest_hash", json!(hash_with('f'))),
                ("seat_attestation_hash", json!(hash_with('f'))),
            ] {
                let mut mutated = package.clone();
                mutated["disposition_bundle"][votes_name][vote_index][pointer_suffix] = value;
                assert_ne!(
                    normalized_final_fixture_hash(&mutated),
                    final_root,
                    "{votes_name}[{vote_index}] {pointer_suffix} mutation escaped final commitment",
                );
                assert!(verify_fixture_package(&mutated).is_err());
            }
            for (signature_field, value) in [
                ("signing_key_id", json!(hash_with('f'))),
                ("signature", json!(repeated_hex('f', 128))),
            ] {
                let mut mutated = package.clone();
                mutated["disposition_bundle"][votes_name][vote_index]["signature"]
                    [signature_field] = value;
                assert_ne!(normalized_final_fixture_hash(&mutated), final_root);
                assert!(verify_fixture_package(&mutated).is_err());
            }
        }
    }

    for proof_index in 0..2 {
        let mut mutated = package.clone();
        mutated["disposition_bundle"]["quorum_proofs"][proof_index]["proof_hash"] =
            json!(hash_with('f'));
        assert_ne!(normalized_final_fixture_hash(&mutated), final_root);
        assert!(verify_fixture_package(&mutated).is_err());
    }
    for field in ["provider_classes", "evidence_classes"] {
        let mut substituted = package.clone();
        substituted["disposition_bundle"]["quorum_proofs"][0][field] =
            if field == "provider_classes" {
                json!(["OpenAI", "Anthropic", "xAI", "IndependentNonProvider"])
            } else {
                json!(["ExternalAudit", "IndependentNonProviderEvidence"])
            };
        let rehashed =
            quorum_proof_fixture_hash(&substituted["disposition_bundle"]["quorum_proofs"][0]);
        substituted["disposition_bundle"]["quorum_proofs"][0]["proof_hash"] = json!(rehashed);
        assert_ne!(normalized_final_fixture_hash(&substituted), final_root);
        assert!(
            verify_fixture_package(&substituted).is_err(),
            "quorum {field} substitution passed after recomputing proof hash",
        );
    }

    let mut lifecycle_mutation = package.clone();
    lifecycle_mutation["protocol_identity"]["lifecycle_state"] = json!("Draft");
    assert_ne!(
        normalized_final_fixture_hash(&lifecycle_mutation),
        final_root
    );
    assert!(verify_fixture_package(&lifecycle_mutation).is_err());

    for pointer in [
        "/disposition_bundle/chair_interventions/0/comment_hash",
        "/disposition_bundle/chair_interventions/0/scope_hash",
        "/disposition_bundle/chair_interventions/0/signature/signing_key_id",
        "/disposition_bundle/chair_interventions/0/signature/signature",
    ] {
        let mut mutated = package.clone();
        *mutated
            .pointer_mut(pointer)
            .expect("fixture Chair mutation pointer") = if pointer.ends_with("/signature") {
            json!(repeated_hex('f', 128))
        } else {
            json!(hash_with('f'))
        };
        assert_ne!(normalized_final_fixture_hash(&mutated), final_root);
        assert!(verify_fixture_package(&mutated).is_err());
    }

    for pointer in [
        "/receipt_manifest/genesis_adoption_receipt/evidence_bundle/chronology_manifest_hash",
        "/receipt_manifest/genesis_adoption_receipt/evidence_bundle_hash",
        "/receipt_manifest/genesis_adoption_receipt/receipt_root",
    ] {
        let mut mutated = package.clone();
        *mutated
            .pointer_mut(pointer)
            .expect("fixture genesis mutation pointer") = json!(hash_with('f'));
        assert_ne!(authorization_target_fixture_hash(&mutated), authorization);
        assert!(verify_fixture_package(&mutated).is_err());
    }

    let mut forged_stored_root = package.clone();
    forged_stored_root["receipt_manifest"]["final_package_root"] = json!(hash_with('f'));
    assert_eq!(
        normalized_final_fixture_hash(&forged_stored_root),
        final_root
    );
    assert_ne!(
        forged_stored_root["receipt_manifest"]["final_package_root"],
        normalized_final_fixture_hash(&forged_stored_root),
        "stored root forgery must fail normalized-preimage verification",
    );
    let forged_root_result = assert_binding_semantics(
        &forged_stored_root,
        &authority_registry,
        &seat_authority_registry,
        Some(&verified_predecessor),
    );
    assert!(
        forged_root_result.is_err(),
        "schema-valid stored-root forgery produced VerifiedPackageRoot",
    );
    let impossible_execution_chain = forged_root_result
        .as_ref()
        .map(|root| current_execution_chain(root, &verified_predecessor, &authority_registry));
    assert!(
        impossible_execution_chain.is_err(),
        "execution-chain creation accepted a raw or forged stored root",
    );

    let artifact_manifest = json!({
        "final_package_root": final_root,
        "renderer_manifest_hash": package["receipt_manifest"]
            ["publication_authorization_receipt"]["renderer_manifest_hash"],
        "canonical_cbor_digest": hash_with('1'),
        "markdown_digest": hash_with('2'),
        "html_digest": hash_with('3'),
        "pdf_a_digest": hash_with('4')
    });
    let artifact_manifest_root = hash_fixture(
        "exo.decision_forum.publication_artifact_manifest.v1",
        &artifact_manifest,
    );
    for field in [
        "final_package_root",
        "renderer_manifest_hash",
        "canonical_cbor_digest",
        "markdown_digest",
        "html_digest",
        "pdf_a_digest",
    ] {
        let mut mutated = artifact_manifest.clone();
        mutated[field] = json!(hash_with('f'));
        assert_ne!(
            hash_fixture(
                "exo.decision_forum.publication_artifact_manifest.v1",
                &mutated
            ),
            artifact_manifest_root,
            "external {field} mutation escaped artifact-manifest commitment",
        );
    }

    let current_chain =
        current_execution_chain(&verified_root, &verified_predecessor, &authority_registry);
    let expectation = ExecutionChainExpectation {
        verified_package_root: &verified_root,
        predecessor_chain_root: &verified_predecessor.chain_root,
        predecessor_terminal_receipt_hash: &verified_predecessor.terminal_receipt_hash,
        predecessor_terminal_sequence: verified_predecessor.terminal_sequence,
        allowed_receipt_kinds: ["ActionExecuted", "ContinuingReview", "AdverseEvent"]
            .into_iter()
            .collect(),
        expected_receipt_count: 3,
    };
    let verified_current =
        verify_execution_chain(&current_chain, &expectation, &authority_registry)
            .expect("nonempty current execution chain must verify");
    assert_eq!(verified_current.first_sequence, 4);
    assert_eq!(verified_current.terminal_sequence, 6);
    for pointer in [
        "/receipts/0/payload_hash",
        "/receipts/0/signature/signature",
        "/receipts/1/previous_receipt_hash",
        "/receipts/2/sequence",
    ] {
        let mut mutated = current_chain.clone();
        *mutated
            .pointer_mut(pointer)
            .expect("fixture execution-chain pointer") = json!(hash_with('f'));
        assert!(
            execution_chain_root(&mutated) != current_chain["chain_root"]
                || verify_execution_chain(&mutated, &expectation, &authority_registry).is_err(),
            "current external execution receipt mutation escaped commitment and verification",
        );
    }
    let mut replay = current_chain.clone();
    let replay_key = replay["receipts"][0]["idempotency_key_hash"].clone();
    replay["receipts"][1]["idempotency_key_hash"] = replay_key;
    assert!(
        verify_execution_chain(&replay, &expectation, &authority_registry).is_err(),
        "replay must fail"
    );

    for (case, pointer, value) in [
        ("wrong tenant", "/tenant_id", json!("tenant-2")),
        ("wrong protocol", "/protocol_id", json!("DF-PROTOCOL-999")),
        (
            "wrong version",
            "/protocol_version_hash",
            json!(hash_with('f')),
        ),
        (
            "wrong authorized root",
            "/authorized_package_root",
            json!(hash_with('f')),
        ),
        (
            "wrong predecessor",
            "/previous_chain_root",
            json!(hash_with('f')),
        ),
        (
            "wrong predecessor terminal hash",
            "/predecessor_terminal_receipt_hash",
            json!(hash_with('f')),
        ),
        (
            "wrong predecessor terminal sequence",
            "/predecessor_terminal_sequence",
            json!(2),
        ),
        ("wrong first sequence", "/first_sequence", json!(1)),
        (
            "wrong terminal",
            "/terminal_receipt_hash",
            json!(hash_with('f')),
        ),
        ("wrong terminal sequence", "/terminal_sequence", json!(5)),
        ("wrong count", "/receipt_count", json!(2)),
        ("wrong kind", "/receipts/0/receipt_kind", json!("Reset")),
        (
            "wrong signing key",
            "/signer_authorities/did:exo:executor-14/signing_key_id",
            json!(hash_with('f')),
        ),
        (
            "forked link",
            "/receipts/1/previous_receipt_hash",
            current_chain["receipts"][0]["previous_receipt_hash"].clone(),
        ),
    ] {
        let mut mutated = current_chain.clone();
        *mutated
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("fixture adversarial pointer {pointer}")) = value;
        mutated["chain_root"] = json!(execution_chain_root(&mutated));
        assert!(
            verify_execution_chain(&mutated, &expectation, &authority_registry).is_err(),
            "{case} adversarial chain passed after recomputing root",
        );
    }

    let trusted_current_authority = authority_registry
        .resolve(
            "tenant-1",
            "DF-PROTOCOL-001",
            "did:exo:executor-14",
            "ProtocolExecutionReceiptV1",
        )
        .expect("fixture current authority");
    for (case, sequences) in [
        ("sequence reset", [1_u64, 2, 3]),
        ("sequence gap", [4_u64, 6, 7]),
        ("duplicate sequence", [4_u64, 4, 5]),
    ] {
        let mut mutated = current_chain.clone();
        for (receipt, sequence) in mutated["receipts"]
            .as_array_mut()
            .expect("fixture receipts")
            .iter_mut()
            .zip(sequences)
        {
            receipt["sequence"] = json!(sequence);
        }
        resign_and_relink_execution_chain(&mut mutated, trusted_current_authority, 14);
        assert!(
            verify_execution_chain(&mutated, &expectation, &authority_registry).is_err(),
            "{case} passed after re-signing, relinking, and recomputing the chain root",
        );
    }

    let (attacker_signing_key_id, attacker_verification_key) = fixture_key_material(15);
    let attacker_authority = VerifiedAuthorityBindingV1 {
        tenant_id: "tenant-1".to_owned(),
        protocol_id: "DF-PROTOCOL-001".to_owned(),
        actor_did: "did:exo:attacker".to_owned(),
        scope: "ProtocolExecutionReceiptV1".to_owned(),
        signing_key_id: attacker_signing_key_id,
        verification_key: attacker_verification_key,
        authority_chain_hash: hash_with('f'),
    };
    let mut authority_substitution = current_chain.clone();
    resign_and_relink_execution_chain(&mut authority_substitution, &attacker_authority, 15);
    assert!(
        verify_execution_chain(&authority_substitution, &expectation, &authority_registry,)
            .is_err(),
        "attacker signer/key/authority substitution passed after valid re-sign and rehash",
    );

    let successor = successor_package(&package, &verified_current);
    let reference = &successor["receipt_manifest"]["prior_execution_receipt_chain"];
    verify_prior_execution_reference(reference, &verified_current)
        .expect("successor must commit current chain exactly");
    for field in [
        "tenant_id",
        "protocol_id",
        "prior_protocol_version_hash",
        "authorized_package_root",
        "previous_chain_root",
        "predecessor_terminal_receipt_hash",
        "predecessor_terminal_sequence",
        "first_sequence",
        "chain_root",
        "terminal_receipt_hash",
        "terminal_sequence",
        "receipt_count",
    ] {
        let mut wrong_reference = reference.clone();
        wrong_reference[field] = if [
            "predecessor_terminal_sequence",
            "first_sequence",
            "terminal_sequence",
            "receipt_count",
        ]
        .contains(&field)
        {
            json!(2)
        } else if field == "tenant_id" {
            json!("tenant-2")
        } else if field == "protocol_id" {
            json!("DF-PROTOCOL-999")
        } else {
            json!(hash_with('f'))
        };
        assert!(
            verify_prior_execution_reference(&wrong_reference, &verified_current).is_err(),
            "successor predecessor reference {field} mutation passed",
        );
    }
}
```

- [ ] **Step 2: Run the schema guard and capture RED**

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract normative_schema_fixes_package_components_and_deterministic_primitives -- --exact --nocapture
```

Expected: `FAIL` with `failed to read
governance/schemas/peer-reviewed-protocol-package-v1.schema.json`. A compile
failure caused by an unpinned/missing validator is invalid RED evidence.

- [ ] **Step 3: Create the complete transport schema**

Create `governance/schemas/peer-reviewed-protocol-package-v1.schema.json`
with an Apache-2.0 license recorded in `$comment` and these exact constraints:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://exochain.org/schemas/decision-forum/peer-reviewed-protocol-package-v1.schema.json",
  "$comment": "Copyright 2026 Exochain Foundation. SPDX-License-Identifier: Apache-2.0. JSON is a transport projection only; authoritative hashing uses domain-separated canonical CBOR.",
  "title": "PeerReviewedProtocolPackageV1",
  "description": "json-transport-only; caller-supplied identifiers; hlc timestamps; authoritative encoding canonical-cbor; hash domain exo.decision_forum.peer_reviewed_protocol_package.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "protocol_identity",
    "protocol_document",
    "protocol_envelope",
    "evidence_manifest",
    "review_bundle",
    "disposition_bundle",
    "monitoring_plan",
    "systemic_learning_manifest",
    "commercial_boundary",
    "receipt_manifest"
  ],
  "properties": {
    "schema_version": { "const": 1 },
    "protocol_identity": { "$ref": "#/$defs/ProtocolIdentity" },
    "protocol_document": { "$ref": "#/$defs/ProtocolDocument" },
    "protocol_envelope": { "$ref": "#/$defs/ProtocolEnvelope" },
    "evidence_manifest": { "$ref": "#/$defs/EvidenceManifest" },
    "review_bundle": { "$ref": "#/$defs/ReviewBundle" },
    "disposition_bundle": { "$ref": "#/$defs/DispositionBundle" },
    "monitoring_plan": { "$ref": "#/$defs/MonitoringPlan" },
    "systemic_learning_manifest": { "$ref": "#/$defs/SystemicLearningManifest" },
    "commercial_boundary": { "$ref": "#/$defs/CommercialBoundary" },
    "receipt_manifest": { "$ref": "#/$defs/ReceiptManifest" }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "disposition_bundle": {
            "properties": {
              "binding_mode": { "const": "BindingInsideRatifiedEnvelope" }
            },
            "required": ["binding_mode"]
          }
        },
        "required": ["disposition_bundle"]
      },
      "then": {
        "properties": {
          "protocol_identity": {
            "properties": { "lifecycle_state": { "const": "Approved" } }
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "protocol_identity": {
            "properties": { "version": { "const": 1 } },
            "required": ["version"]
          }
        },
        "required": ["protocol_identity"]
      },
      "then": {
        "properties": {
          "protocol_identity": {
            "properties": { "prior_version_hash": { "type": "null" } }
          },
          "receipt_manifest": {
            "properties": { "prior_execution_receipt_chain": { "type": "null" } }
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "protocol_identity": {
            "properties": { "version": { "type": "integer", "minimum": 2 } },
            "required": ["version"]
          }
        },
        "required": ["protocol_identity"]
      },
      "then": {
        "properties": {
          "protocol_identity": {
            "properties": { "prior_version_hash": { "$ref": "#/$defs/Hash256" } }
          },
          "receipt_manifest": {
            "properties": {
              "prior_execution_receipt_chain": {
                "$ref": "#/$defs/PriorExecutionReceiptChainReferenceV1"
              }
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "Hash256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "Did": {
      "type": "string",
      "pattern": "^did:exo:[A-Za-z0-9_:-]+$"
    },
    "Uuid": {
      "type": "string",
      "format": "uuid",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    },
    "Timestamp": {
      "type": "object",
      "additionalProperties": false,
      "required": ["physical_ms", "logical"],
      "properties": {
        "physical_ms": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "logical": { "type": "integer", "minimum": 0, "maximum": 4294967295 }
      }
    },
    "GitObjectId": {
      "type": "object",
      "additionalProperties": false,
      "required": ["algorithm", "digest"],
      "properties": {
        "algorithm": { "const": "sha1" },
        "digest": { "type": "string", "pattern": "^[0-9a-f]{40}$" }
      }
    },
    "ProviderClass": {
      "enum": [
        "OpenAI", "Anthropic", "xAI", "AlphabetGoogleGemini",
        "IndependentNonProvider"
      ]
    },
    "EvidenceClass": {
      "description": "Complete non-binding evidence inventory vocabulary. ProviderModelJudgment is retained for provider/seat provenance but cannot satisfy an independent evidence floor.",
      "enum": [
        "ProviderModelJudgment", "DeterministicTest", "ReproducibleBenchmark",
        "AttestedExecution", "IndependentHumanReview", "FormalVerification",
        "ExternalAudit", "IndependentNonProviderEvidence"
      ]
    },
    "IndependentEvidenceClass": {
      "description": "Closed binding and E-STOP evidence-floor vocabulary. Provider prose and ProviderModelJudgment are intentionally unrepresentable.",
      "enum": [
        "DeterministicTest", "ReproducibleBenchmark", "AttestedExecution",
        "IndependentHumanReview", "FormalVerification", "ExternalAudit",
        "IndependentNonProviderEvidence"
      ]
    },
    "ResourceCeilings": {
      "description": "Sorted ResourceKind-to-integer-unit map; Rust rebuilds this projection as BTreeMap<ResourceKind, u64> before canonical CBOR hashing.",
      "type": "object",
      "minProperties": 1,
      "additionalProperties": false,
      "properties": {
        "action_count": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "compute_milliseconds": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "memory_bytes": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "storage_bytes": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "network_egress_bytes": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "token_count": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "cost_micro_units": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 }
      }
    },
    "BctsState": {
      "enum": [
        "Draft", "Submitted", "IdentityResolved", "ConsentValidated",
        "Deliberated", "Verified", "Governed", "Approved", "Executed",
        "Recorded", "Closed", "Denied", "Escalated", "Remediated"
      ]
    },
    "HashReference": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "content_hash", "media_type"],
      "properties": {
        "kind": { "type": "string", "minLength": 1 },
        "content_hash": { "$ref": "#/$defs/Hash256" },
        "media_type": { "type": "string", "minLength": 1 }
      }
    },
    "CouncilDispositionSignature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature", "signed_payload_hash",
        "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "CouncilDispositionV1" }
      }
    },
    "AiIrbDispositionSignature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature", "signed_payload_hash",
        "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "AiIrbDispositionV1" }
      }
    },
    "AuthorityChainReferenceV1": {
      "description": "Typed projection of a prior kernel/authority-chain verification result. Seat entries match VerifiedSeatAuthorityRegistryV1; non-seat entries match VerifiedAuthorityRegistryV1. Package fields cannot self-authorize.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "binding_kind", "tenant_id", "protocol_id", "actor_did", "controller_did",
        "scope", "signing_key_id",
        "verification_key", "authority_chain_hash"
      ],
      "properties": {
        "binding_kind": { "enum": ["SeatAuthority", "NonSeatAuthority"] },
        "tenant_id": { "type": "string", "minLength": 1 },
        "protocol_id": { "type": "string", "minLength": 1 },
        "actor_did": { "$ref": "#/$defs/Did" },
        "controller_did": { "$ref": "#/$defs/Did" },
        "scope": {
          "enum": [
            "CouncilSeatV1", "AiIrbSeatV1",
            "ChairInterventionV1", "PublicationAuthorizationReceiptV1",
            "ProtocolExecutionReceiptV1"
          ]
        },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "authority_chain_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ChairAuthorityV1": {
      "description": "Resolvable Chair signing-key attestation used only for ChairInterventionSigningPayloadV1 verification.",
      "type": "object",
      "additionalProperties": false,
      "required": ["chair_did", "signing_key_id", "verification_key", "authority_chain_hash"],
      "properties": {
        "chair_did": { "$ref": "#/$defs/Did" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "authority_chain_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ChairInterventionSignature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature", "signed_payload_hash",
        "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "ChairInterventionV1" }
      }
    },
    "PublicationAuthorizationSignature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature", "signed_payload_hash",
        "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "PublicationAuthorizationReceiptV1" }
      }
    },
    "CouncilDisposition": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "disposition_id", "seat_id", "seat_kind", "choice", "authorization_target_hash",
        "protocol_version_hash", "review_bundle_hash", "eligible_set_hash",
        "seat_attestation_hash", "context_manifest_hash", "signed_at", "signature"
      ],
      "properties": {
        "disposition_id": { "$ref": "#/$defs/Uuid" },
        "seat_id": { "$ref": "#/$defs/Did" },
        "seat_kind": { "const": "Council" },
        "choice": { "enum": ["Approve", "Reject", "Abstain"] },
        "authorization_target_hash": { "$ref": "#/$defs/Hash256" },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "review_bundle_hash": { "$ref": "#/$defs/Hash256" },
        "eligible_set_hash": { "$ref": "#/$defs/Hash256" },
        "seat_attestation_hash": { "$ref": "#/$defs/Hash256" },
        "context_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "signed_at": { "$ref": "#/$defs/Timestamp" },
        "signature": { "$ref": "#/$defs/CouncilDispositionSignature" }
      }
    },
    "AiIrbDisposition": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "disposition_id", "seat_id", "seat_kind", "choice", "authorization_target_hash",
        "protocol_version_hash", "review_bundle_hash", "eligible_set_hash",
        "seat_attestation_hash", "context_manifest_hash", "signed_at", "signature"
      ],
      "properties": {
        "disposition_id": { "$ref": "#/$defs/Uuid" },
        "seat_id": { "$ref": "#/$defs/Did" },
        "seat_kind": { "const": "AiIrb" },
        "choice": { "enum": ["Approve", "Reject", "Abstain"] },
        "authorization_target_hash": { "$ref": "#/$defs/Hash256" },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "review_bundle_hash": { "$ref": "#/$defs/Hash256" },
        "eligible_set_hash": { "$ref": "#/$defs/Hash256" },
        "seat_attestation_hash": { "$ref": "#/$defs/Hash256" },
        "context_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "signed_at": { "$ref": "#/$defs/Timestamp" },
        "signature": { "$ref": "#/$defs/AiIrbDispositionSignature" }
      }
    },
    "SeatAttestationSignature": {
      "description": "Controller signature over exact domain-separated canonical CBOR of SeatAttestationSigningPayloadV1. The controller key resolves only from VerifiedSeatAuthorityRegistryV1.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature",
        "signed_payload_hash", "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "SeatAttestationV1" }
      }
    },
    "SeatAttestation": {
      "description": "Signed package claim matched byte-for-byte and cryptographically against an independently produced VerifiedSeatAuthorityRegistryV1 binding; never a source of trusted review or vote keys.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "tenant_id", "protocol_id", "seat_id", "seat_kind", "provider_class", "controller_did",
        "independent_control_proof_hash",
        "reviewer_identifier", "observable_version", "system_configuration_hash",
        "sampling_parameters_hash", "tool_policy_hash", "context_manifest_hash",
        "behavioral_fingerprint_hash", "signing_key_id", "verification_key",
        "valid_from", "valid_until",
        "evidence_classes", "conflict_declaration_hash", "authority_scope",
        "authority_chain_hash", "signature"
      ],
      "properties": {
        "tenant_id": { "type": "string", "minLength": 1 },
        "protocol_id": { "type": "string", "minLength": 1 },
        "seat_id": { "$ref": "#/$defs/Did" },
        "seat_kind": { "enum": ["Council", "AiIrb"] },
        "provider_class": { "$ref": "#/$defs/ProviderClass" },
        "controller_did": { "$ref": "#/$defs/Did" },
        "independent_control_proof_hash": {
          "oneOf": [{ "$ref": "#/$defs/Hash256" }, { "type": "null" }]
        },
        "reviewer_identifier": { "type": "string", "minLength": 1 },
        "observable_version": { "type": "string", "minLength": 1 },
        "system_configuration_hash": { "$ref": "#/$defs/Hash256" },
        "sampling_parameters_hash": { "$ref": "#/$defs/Hash256" },
        "tool_policy_hash": { "$ref": "#/$defs/Hash256" },
        "context_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "behavioral_fingerprint_hash": { "$ref": "#/$defs/Hash256" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "valid_from": { "$ref": "#/$defs/Timestamp" },
        "valid_until": { "$ref": "#/$defs/Timestamp" },
        "evidence_classes": {
          "type": "array", "minItems": 1, "uniqueItems": true,
          "items": { "$ref": "#/$defs/EvidenceClass" }
        },
        "conflict_declaration_hash": { "$ref": "#/$defs/Hash256" },
        "authority_scope": { "enum": ["CouncilSeatV1", "AiIrbSeatV1"] },
        "authority_chain_hash": { "$ref": "#/$defs/Hash256" },
        "signature": { "$ref": "#/$defs/SeatAttestationSignature" }
      }
    },
    "CouncilSeatAttestation": {
      "allOf": [
        { "$ref": "#/$defs/SeatAttestation" },
        { "properties": {
          "seat_kind": { "const": "Council" },
          "authority_scope": { "const": "CouncilSeatV1" }
        } }
      ]
    },
    "AiIrbSeatAttestation": {
      "allOf": [
        { "$ref": "#/$defs/SeatAttestation" },
        { "properties": {
          "seat_kind": { "const": "AiIrb" },
          "authority_scope": { "const": "AiIrbSeatV1" }
        } }
      ]
    },
    "CouncilRoster": {
      "type": "object",
      "additionalProperties": false,
      "required": ["openai", "anthropic", "xai", "alphabet_google_gemini", "independent_non_provider"],
      "properties": {
        "openai": { "allOf": [{ "$ref": "#/$defs/CouncilSeatAttestation" }, { "properties": { "provider_class": { "const": "OpenAI" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "anthropic": { "allOf": [{ "$ref": "#/$defs/CouncilSeatAttestation" }, { "properties": { "provider_class": { "const": "Anthropic" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "xai": { "allOf": [{ "$ref": "#/$defs/CouncilSeatAttestation" }, { "properties": { "provider_class": { "const": "xAI" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "alphabet_google_gemini": { "allOf": [{ "$ref": "#/$defs/CouncilSeatAttestation" }, { "properties": { "provider_class": { "const": "AlphabetGoogleGemini" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "independent_non_provider": {
          "allOf": [
            { "$ref": "#/$defs/CouncilSeatAttestation" },
            {
              "properties": {
                "provider_class": { "const": "IndependentNonProvider" },
                "independent_control_proof_hash": { "$ref": "#/$defs/Hash256" },
                "evidence_classes": {
                  "contains": { "const": "IndependentNonProviderEvidence" },
                  "minContains": 1
                }
              }
            }
          ]
        }
      }
    },
    "AiIrbRoster": {
      "type": "object",
      "additionalProperties": false,
      "required": ["openai", "anthropic", "xai", "alphabet_google_gemini", "independent_non_provider"],
      "properties": {
        "openai": { "allOf": [{ "$ref": "#/$defs/AiIrbSeatAttestation" }, { "properties": { "provider_class": { "const": "OpenAI" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "anthropic": { "allOf": [{ "$ref": "#/$defs/AiIrbSeatAttestation" }, { "properties": { "provider_class": { "const": "Anthropic" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "xai": { "allOf": [{ "$ref": "#/$defs/AiIrbSeatAttestation" }, { "properties": { "provider_class": { "const": "xAI" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "alphabet_google_gemini": { "allOf": [{ "$ref": "#/$defs/AiIrbSeatAttestation" }, { "properties": { "provider_class": { "const": "AlphabetGoogleGemini" }, "independent_control_proof_hash": { "type": "null" } } }] },
        "independent_non_provider": {
          "allOf": [
            { "$ref": "#/$defs/AiIrbSeatAttestation" },
            {
              "properties": {
                "provider_class": { "const": "IndependentNonProvider" },
                "independent_control_proof_hash": { "$ref": "#/$defs/Hash256" },
                "evidence_classes": {
                  "contains": { "const": "IndependentNonProviderEvidence" },
                  "minContains": 1
                }
              }
            }
          ]
        }
      }
    },
    "ReviewAssignment": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "assignment_id", "seat_id", "seat_kind", "protocol_version_hash",
        "seat_attestation_hash", "context_manifest_hash", "review_role",
        "blind_commitment", "conflict_declaration_hash", "assigned_at"
      ],
      "properties": {
        "assignment_id": { "$ref": "#/$defs/Uuid" },
        "seat_id": { "$ref": "#/$defs/Did" },
        "seat_kind": { "enum": ["Council", "AiIrb"] },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "seat_attestation_hash": { "$ref": "#/$defs/Hash256" },
        "context_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "review_role": { "enum": ["Governance", "Legal", "Architecture", "Security", "Operations", "RiskBenefit", "Monitoring", "AdverseEvent", "ProgressiveEvent", "CorrectiveAction"] },
        "blind_commitment": { "$ref": "#/$defs/Hash256" },
        "conflict_declaration_hash": { "$ref": "#/$defs/Hash256" },
        "assigned_at": { "$ref": "#/$defs/Timestamp" }
      }
    },
    "PeerReviewSignature": {
      "description": "Ed25519 envelope for the domain-separated canonical PeerReviewSigningPayloadV1. The payload contains the complete review body fields and the common authorization_target_hash; the trusted signing key resolves through assignment_id only from the opaque, independently produced VerifiedSeatAuthorityRegistryV1, never from an in-package seat attestation.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature", "signed_payload_hash",
        "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "PeerReviewV1" }
      }
    },
    "PeerReview": {
      "description": "Signed peer review. Canonical PeerReviewSigningPayloadV1 contains review_id, assignment_id, protocol_version_hash, criteria_results_hash, review_body_hash, disposition, sealed_at, and authorization_target_hash under domain exo.decision_forum.peer_review_signing_payload.v1.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "review_id", "assignment_id", "protocol_version_hash", "criteria_results_hash",
        "review_body_hash", "disposition", "sealed_at", "authorization_target_hash",
        "signature"
      ],
      "properties": {
        "review_id": { "$ref": "#/$defs/Uuid" },
        "assignment_id": { "$ref": "#/$defs/Uuid" },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "criteria_results_hash": { "$ref": "#/$defs/Hash256" },
        "review_body_hash": { "$ref": "#/$defs/Hash256" },
        "disposition": { "enum": ["Approve", "ChangesRequired", "Reject"] },
        "sealed_at": { "$ref": "#/$defs/Timestamp" },
        "authorization_target_hash": { "$ref": "#/$defs/Hash256" },
        "signature": { "$ref": "#/$defs/PeerReviewSignature" }
      }
    },
    "ReviewResolution": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "resolution_id", "review_id", "comment_hash", "author_response_hash",
        "revision_diff_hash", "resolution", "resolved_at", "signature_hash"
      ],
      "properties": {
        "resolution_id": { "$ref": "#/$defs/Uuid" },
        "review_id": { "$ref": "#/$defs/Uuid" },
        "comment_hash": { "$ref": "#/$defs/Hash256" },
        "author_response_hash": { "$ref": "#/$defs/Hash256" },
        "revision_diff_hash": { "$ref": "#/$defs/Hash256" },
        "resolution": { "enum": ["Accepted", "ReasonedRejection", "UnresolvedMinorityReport"] },
        "resolved_at": { "$ref": "#/$defs/Timestamp" },
        "signature_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "DissentRecord": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "dissent_id", "seat_id", "context", "body_hash", "effect", "recorded_at",
        "chair_alert_receipt_hash", "signature_hash"
      ],
      "properties": {
        "dissent_id": { "$ref": "#/$defs/Uuid" },
        "seat_id": { "$ref": "#/$defs/Did" },
        "context": { "enum": ["Authorization", "Monitoring"] },
        "body_hash": { "$ref": "#/$defs/Hash256" },
        "effect": { "enum": ["AuthorizationBlocked", "ChairAlertAndContinuingReview"] },
        "recorded_at": { "$ref": "#/$defs/Timestamp" },
        "chair_alert_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "signature_hash": { "$ref": "#/$defs/Hash256" }
      },
      "allOf": [
        {
          "if": {
            "required": ["context"],
            "properties": { "context": { "const": "Authorization" } }
          },
          "then": { "properties": { "effect": { "const": "AuthorizationBlocked" } } }
        },
        {
          "if": {
            "required": ["context"],
            "properties": { "context": { "const": "Monitoring" } }
          },
          "then": {
            "properties": {
              "effect": { "const": "ChairAlertAndContinuingReview" }
            }
          }
        }
      ]
    },
    "QuorumProof": {
      "description": "Eligible-unanimity proof whose evidence_classes is the exact IndependentEvidenceClass set from EvidenceManifest.independent_evidence_classes.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "proof_id", "seat_kind", "eligible_seat_hashes", "approve_seat_hashes",
        "provider_classes", "evidence_classes", "eligible_count", "approve_count",
        "required_count", "result", "computed_at", "proof_hash"
      ],
      "properties": {
        "proof_id": { "$ref": "#/$defs/Uuid" },
        "seat_kind": { "enum": ["Council", "AiIrb"] },
        "eligible_seat_hashes": { "type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "approve_seat_hashes": { "type": "array", "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "provider_classes": { "type": "array", "minItems": 4, "maxItems": 4, "uniqueItems": true, "items": { "$ref": "#/$defs/ProviderClass" } },
        "evidence_classes": { "type": "array", "minItems": 2, "uniqueItems": true, "items": { "$ref": "#/$defs/IndependentEvidenceClass" } },
        "eligible_count": { "const": 5 },
        "approve_count": { "type": "integer", "minimum": 0, "maximum": 5 },
        "required_count": { "const": 5 },
        "result": { "enum": ["EligibleUnanimity", "NotUnanimous", "ProviderFloorFailed", "EvidenceFloorFailed"] },
        "computed_at": { "$ref": "#/$defs/Timestamp" },
        "proof_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ChairIntervention": {
      "description": "Signed Chair intervention. ChairInterventionSigningPayloadV1 is every field except signature under domain exo.decision_forum.chair_intervention_signing_payload.v1; authority resolves through ProtocolIdentity.chair_authority.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "intervention_id", "chair_did", "choice", "scope_hash", "effect",
        "comment_hash", "authorization_target_hash", "protocol_version_hash",
        "signed_at", "signature"
      ],
      "properties": {
        "intervention_id": { "$ref": "#/$defs/Uuid" },
        "chair_did": { "$ref": "#/$defs/Did" },
        "choice": { "enum": ["Approve", "Reject", "Abstain", "Comment"] },
        "scope_hash": { "$ref": "#/$defs/Hash256" },
        "effect": { "enum": ["EndorsementOnly", "ScopedHumanOverrideHold", "NoAuthorityEffect"] },
        "comment_hash": { "$ref": "#/$defs/Hash256" },
        "authorization_target_hash": { "$ref": "#/$defs/Hash256" },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "signed_at": { "$ref": "#/$defs/Timestamp" },
        "signature": { "$ref": "#/$defs/ChairInterventionSignature" }
      },
      "allOf": [
        {
          "if": {
            "required": ["choice"],
            "properties": { "choice": { "const": "Approve" } }
          },
          "then": { "properties": { "effect": { "const": "EndorsementOnly" } } }
        },
        {
          "if": {
            "required": ["choice"],
            "properties": { "choice": { "const": "Reject" } }
          },
          "then": {
            "properties": { "effect": { "const": "ScopedHumanOverrideHold" } }
          }
        },
        {
          "if": {
            "required": ["choice"],
            "properties": { "choice": { "enum": ["Abstain", "Comment"] } }
          },
          "then": { "properties": { "effect": { "const": "NoAuthorityEffect" } } }
        }
      ]
    },
    "ProtocolEvent": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "event_id", "event_kind", "severity_basis_points", "expectedness", "relatedness_basis_points",
        "affected_claim_hashes", "evidence_hashes", "reporter_did", "occurred_at",
        "immediate_containment_hash", "disposition_hash", "scope_hash", "receipt_root"
      ],
      "properties": {
        "event_id": { "$ref": "#/$defs/Uuid" },
        "event_kind": { "enum": ["ProgressiveEvent", "AdverseEvent", "UnanticipatedProblem", "AiSdlcTransgression", "Estop"] },
        "severity_basis_points": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "expectedness": { "enum": ["Expected", "Unexpected", "Unknown"] },
        "relatedness_basis_points": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "affected_claim_hashes": { "type": "array", "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "evidence_hashes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "reporter_did": { "$ref": "#/$defs/Did" },
        "occurred_at": { "$ref": "#/$defs/Timestamp" },
        "immediate_containment_hash": { "$ref": "#/$defs/Hash256" },
        "disposition_hash": { "$ref": "#/$defs/Hash256" },
        "scope_hash": { "$ref": "#/$defs/Hash256" },
        "receipt_root": { "$ref": "#/$defs/Hash256" }
      }
    },
    "AarRcaAttestation": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "attestation_id", "event_id", "investigator_did", "signer_kind", "aar_hash",
        "rca_hash", "attested_at", "signature_hash"
      ],
      "properties": {
        "attestation_id": { "$ref": "#/$defs/Uuid" },
        "event_id": { "$ref": "#/$defs/Uuid" },
        "investigator_did": { "$ref": "#/$defs/Did" },
        "signer_kind": { "const": "Human" },
        "aar_hash": { "$ref": "#/$defs/Hash256" },
        "rca_hash": { "$ref": "#/$defs/Hash256" },
        "attested_at": { "$ref": "#/$defs/Timestamp" },
        "signature_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "CapaRecord": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "capa_id", "event_id", "corrective_action_hashes", "preventive_action_hashes",
        "owner_did", "completed_at", "completion_evidence_hash", "receipt_root"
      ],
      "properties": {
        "capa_id": { "$ref": "#/$defs/Uuid" },
        "event_id": { "$ref": "#/$defs/Uuid" },
        "corrective_action_hashes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "preventive_action_hashes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "owner_did": { "$ref": "#/$defs/Did" },
        "completed_at": { "$ref": "#/$defs/Timestamp" },
        "completion_evidence_hash": { "$ref": "#/$defs/Hash256" },
        "receipt_root": { "$ref": "#/$defs/Hash256" }
      }
    },
    "EstopAuthorization": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "estop_id", "scope_hash", "active_provider_classes", "approve_provider_classes",
        "required_provider_class_count", "independent_evidence_classes", "threshold_result",
        "fired_at", "receipt_root"
      ],
      "properties": {
        "estop_id": { "$ref": "#/$defs/Uuid" },
        "scope_hash": { "$ref": "#/$defs/Hash256" },
        "active_provider_classes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/ProviderClass" } },
        "approve_provider_classes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/ProviderClass" } },
        "required_provider_class_count": { "type": "integer", "minimum": 1 },
        "independent_evidence_classes": {
          "type": "array", "minItems": 2, "uniqueItems": true,
          "items": { "$ref": "#/$defs/IndependentEvidenceClass" },
          "contains": { "const": "IndependentNonProviderEvidence" },
          "minContains": 1
        },
        "threshold_result": { "enum": ["Fired", "NotMet"] },
        "fired_at": { "$ref": "#/$defs/Timestamp" },
        "receipt_root": { "$ref": "#/$defs/Hash256" }
      }
    },
    "NotificationDeliveryReceipt": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "delivery_id", "event_id", "destination", "attempt_status", "attempted_at",
        "delivery_evidence_hash", "receipt_hash"
      ],
      "properties": {
        "delivery_id": { "$ref": "#/$defs/Uuid" },
        "event_id": { "$ref": "#/$defs/Uuid" },
        "destination": { "type": "string", "minLength": 1 },
        "attempt_status": { "enum": ["Delivered", "Failed"] },
        "attempted_at": { "$ref": "#/$defs/Timestamp" },
        "delivery_evidence_hash": { "$ref": "#/$defs/Hash256" },
        "receipt_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ResetAuthorization": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "reset_id", "stopped_scope_hash", "new_protocol_version_hash", "aar_rca_attestation_hash",
        "capa_record_hash", "recurrence_evidence_hash", "council_quorum_proof_hash",
        "ai_irb_quorum_proof_hash", "chair_signature_hash", "authorized_at"
      ],
      "properties": {
        "reset_id": { "$ref": "#/$defs/Uuid" },
        "stopped_scope_hash": { "$ref": "#/$defs/Hash256" },
        "new_protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "aar_rca_attestation_hash": { "$ref": "#/$defs/Hash256" },
        "capa_record_hash": { "$ref": "#/$defs/Hash256" },
        "recurrence_evidence_hash": { "$ref": "#/$defs/Hash256" },
        "council_quorum_proof_hash": { "$ref": "#/$defs/Hash256" },
        "ai_irb_quorum_proof_hash": { "$ref": "#/$defs/Hash256" },
        "chair_signature_hash": { "$ref": "#/$defs/Hash256" },
        "authorized_at": { "$ref": "#/$defs/Timestamp" }
      }
    },
    "PhasePromotion": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "promotion_id", "from_phase", "to_phase", "envelope_hash", "progressive_event_id",
        "council_quorum_proof_hash", "ai_irb_quorum_proof_hash", "chair_notice_receipt_hash",
        "promoted_at"
      ],
      "properties": {
        "promotion_id": { "$ref": "#/$defs/Uuid" },
        "from_phase": { "type": "string", "minLength": 1 },
        "to_phase": { "type": "string", "minLength": 1 },
        "envelope_hash": { "$ref": "#/$defs/Hash256" },
        "progressive_event_id": { "$ref": "#/$defs/Uuid" },
        "council_quorum_proof_hash": { "$ref": "#/$defs/Hash256" },
        "ai_irb_quorum_proof_hash": { "$ref": "#/$defs/Hash256" },
        "chair_notice_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "promoted_at": { "$ref": "#/$defs/Timestamp" }
      }
    },
    "SystemicLearningRecord": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "record_id", "source_event_id", "prior_assumption_hash", "observed_evidence_hash",
        "causal_confidence_basis_points", "changed_control_hashes", "recurrence_result_hash",
        "affected_claim_hash", "candidate_roadmap_scenario_hashes", "authority_effect"
      ],
      "properties": {
        "record_id": { "$ref": "#/$defs/Uuid" },
        "source_event_id": { "$ref": "#/$defs/Uuid" },
        "prior_assumption_hash": { "$ref": "#/$defs/Hash256" },
        "observed_evidence_hash": { "$ref": "#/$defs/Hash256" },
        "causal_confidence_basis_points": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "changed_control_hashes": { "type": "array", "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "recurrence_result_hash": { "$ref": "#/$defs/Hash256" },
        "affected_claim_hash": { "$ref": "#/$defs/Hash256" },
        "candidate_roadmap_scenario_hashes": { "type": "array", "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "authority_effect": { "const": "ContextOnlyNoEnactmentAuthority" }
      }
    },
    "GenesisEvidenceBundleV1": {
      "description": "Pre-activation evidence only. The canonical body contains exactly typed historical Git IDs, chronology_manifest_hash, and historical_review_evidence_hash; it cannot name a current package or authorization root.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "historical_commit_ids", "chronology_manifest_hash",
        "historical_review_evidence_hash"
      ],
      "properties": {
        "historical_commit_ids": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "#/$defs/GitObjectId" } },
        "chronology_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "historical_review_evidence_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "GenesisAdoptionReceipt": {
      "description": "Prospective genesis receipt. evidence_bundle_hash uses exo.decision_forum.genesis_evidence_bundle.v1. receipt_root uses exo.decision_forum.genesis_adoption_receipt.v1 after normalizing only receipt_root to 32 zero bytes.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "receipt_id", "protocol_id", "pre_activation", "evidence_bundle_hash",
        "evidence_bundle", "prospective_effect_starts_at",
        "retroactive_signature_claimed", "receipt_root"
      ],
      "properties": {
        "receipt_id": { "$ref": "#/$defs/Uuid" },
        "protocol_id": { "type": "string", "minLength": 1 },
        "pre_activation": { "const": true },
        "evidence_bundle_hash": { "$ref": "#/$defs/Hash256" },
        "evidence_bundle": { "$ref": "#/$defs/GenesisEvidenceBundleV1" },
        "prospective_effect_starts_at": { "$ref": "#/$defs/Timestamp" },
        "retroactive_signature_claimed": { "const": false },
        "receipt_root": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ProtocolIdentity": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "protocol_id", "tenant_id", "constitutional_hash", "version",
        "prior_version_hash", "lifecycle_state", "co_pi_dids", "chair_did",
        "chair_authority", "domain"
      ],
      "properties": {
        "protocol_id": { "type": "string", "minLength": 1 },
        "tenant_id": { "type": "string", "minLength": 1 },
        "constitutional_hash": { "$ref": "#/$defs/Hash256" },
        "version": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "prior_version_hash": {
          "oneOf": [{ "$ref": "#/$defs/Hash256" }, { "type": "null" }]
        },
        "lifecycle_state": { "$ref": "#/$defs/BctsState" },
        "co_pi_dids": {
          "type": "array", "minItems": 2, "uniqueItems": true,
          "items": { "$ref": "#/$defs/Did" }
        },
        "chair_did": { "$ref": "#/$defs/Did" },
        "chair_authority": { "$ref": "#/$defs/ChairAuthorityV1" },
        "domain": { "type": "string", "minLength": 1 }
      }
    },
    "ProtocolDocument": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "abstract_text", "purpose", "hypotheses", "scope", "architecture",
        "methods", "implementation_controls", "risks", "benefits",
        "consent_bailment_basis", "data_handling", "threat_model", "monitoring",
        "stopping_rules", "evaluation_method", "implementation_test_plan",
        "claims", "closeout_criteria"
      ],
      "properties": {
        "abstract_text": { "type": "string", "minLength": 1 },
        "purpose": { "type": "string", "minLength": 1 },
        "hypotheses": { "type": "array", "items": { "type": "string", "minLength": 1 } },
        "scope": { "type": "string", "minLength": 1 },
        "architecture": { "type": "string", "minLength": 1 },
        "methods": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "implementation_controls": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "risks": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "benefits": { "type": "array", "items": { "type": "string", "minLength": 1 } },
        "consent_bailment_basis": { "type": "string", "minLength": 1 },
        "data_handling": { "type": "string", "minLength": 1 },
        "threat_model": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "monitoring": { "type": "string", "minLength": 1 },
        "stopping_rules": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "evaluation_method": { "type": "string", "minLength": 1 },
        "implementation_test_plan": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "claims": { "type": "array", "items": { "$ref": "#/$defs/HashReference" } },
        "closeout_criteria": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } }
      }
    },
    "ProtocolEnvelope": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "permitted_actions", "systems", "tenants", "datasets", "actor_classes",
        "resource_ceilings", "risk_ceiling_basis_points", "starts_at",
        "ends_at", "phase_ladder"
      ],
      "properties": {
        "permitted_actions": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } },
        "systems": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } },
        "tenants": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } },
        "datasets": { "type": "array", "uniqueItems": true, "items": { "$ref": "#/$defs/Hash256" } },
        "actor_classes": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } },
        "resource_ceilings": { "$ref": "#/$defs/ResourceCeilings" },
        "risk_ceiling_basis_points": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "starts_at": { "$ref": "#/$defs/Timestamp" },
        "ends_at": { "$ref": "#/$defs/Timestamp" },
        "phase_ladder": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } }
      }
    },
    "EvidenceManifest": {
      "description": "Binding independent-evidence floor. Non-binding ProviderModelJudgment inventory remains in seat attestations and cannot appear in independent_evidence_classes.",
      "type": "object",
      "additionalProperties": false,
      "required": ["items", "independent_evidence_classes", "negative_or_inconclusive_results"],
      "properties": {
        "items": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/HashReference" } },
        "independent_evidence_classes": {
          "type": "array", "minItems": 2, "uniqueItems": true,
          "items": { "$ref": "#/$defs/IndependentEvidenceClass" },
          "contains": { "const": "IndependentNonProviderEvidence" },
          "minContains": 1
        },
        "negative_or_inconclusive_results": { "type": "array", "items": { "$ref": "#/$defs/HashReference" } }
      }
    },
    "ReviewBundle": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "council_seat_attestations", "ai_irb_seat_attestations", "assignments", "blind_commitments", "conflict_declarations",
        "signed_reviews", "author_responses", "revision_diffs", "resolution_matrix",
        "reveal_package_hash"
      ],
      "properties": {
        "council_seat_attestations": { "$ref": "#/$defs/CouncilRoster" },
        "ai_irb_seat_attestations": { "$ref": "#/$defs/AiIrbRoster" },
        "assignments": { "type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": { "$ref": "#/$defs/ReviewAssignment" } },
        "blind_commitments": { "type": "array", "items": { "$ref": "#/$defs/Hash256" } },
        "conflict_declarations": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/HashReference" } },
        "signed_reviews": { "type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": { "$ref": "#/$defs/PeerReview" } },
        "author_responses": { "type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": { "$ref": "#/$defs/HashReference" } },
        "revision_diffs": { "type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": { "$ref": "#/$defs/HashReference" } },
        "resolution_matrix": { "type": "array", "minItems": 10, "maxItems": 10, "uniqueItems": true, "items": { "$ref": "#/$defs/ReviewResolution" } },
        "reveal_package_hash": {
          "oneOf": [{ "$ref": "#/$defs/Hash256" }, { "type": "null" }]
        }
      }
    },
    "DispositionBundle": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "council_eligible_set", "ai_irb_eligible_set", "council_votes", "ai_irb_votes",
        "dissents", "quorum_proofs", "chair_interventions", "kernel_verdicts",
        "authority_chain", "binding_mode"
      ],
      "properties": {
        "council_eligible_set": { "type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/Did" } },
        "ai_irb_eligible_set": { "type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/Did" } },
        "council_votes": { "type": "array", "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/CouncilDisposition" } },
        "ai_irb_votes": { "type": "array", "maxItems": 5, "uniqueItems": true, "items": { "$ref": "#/$defs/AiIrbDisposition" } },
        "dissents": { "type": "array", "items": { "$ref": "#/$defs/DissentRecord" } },
        "quorum_proofs": { "type": "array", "minItems": 2, "maxItems": 2, "uniqueItems": true, "items": { "$ref": "#/$defs/QuorumProof" } },
        "chair_interventions": { "type": "array", "items": { "$ref": "#/$defs/ChairIntervention" } },
        "kernel_verdicts": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/HashReference" } },
        "authority_chain": { "type": "array", "minItems": 12, "maxItems": 12, "uniqueItems": true, "items": { "$ref": "#/$defs/AuthorityChainReferenceV1" } },
        "binding_mode": { "enum": ["Advisory", "BindingInsideRatifiedEnvelope"] }
      },
      "allOf": [
        {
          "if": {
            "required": ["binding_mode"],
            "properties": { "binding_mode": { "const": "BindingInsideRatifiedEnvelope" } }
          },
          "then": {
            "properties": {
              "council_votes": {
                "minItems": 5,
                "items": { "allOf": [{ "$ref": "#/$defs/CouncilDisposition" }, { "properties": { "choice": { "const": "Approve" } } }] }
              },
              "ai_irb_votes": {
                "minItems": 5,
                "items": { "allOf": [{ "$ref": "#/$defs/AiIrbDisposition" }, { "properties": { "choice": { "const": "Approve" } } }] }
              },
              "dissents": {
                "items": { "allOf": [{ "$ref": "#/$defs/DissentRecord" }, { "properties": { "context": { "const": "Monitoring" } } }] }
              },
              "quorum_proofs": { "minItems": 2 }
            }
          }
        }
      ]
    },
    "MonitoringPlan": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "max_iterations", "success_stop_condition", "repeat_failure_limit",
        "escalation_destination", "scheduled_interval_hlc_units", "claim_thresholds",
        "adverse_event_definitions", "progressive_event_definitions", "reporting_destinations",
        "event_payload_type_domains"
      ],
      "properties": {
        "max_iterations": { "type": "integer", "minimum": 1, "maximum": 25 },
        "success_stop_condition": { "type": "string", "minLength": 1 },
        "repeat_failure_limit": { "const": 2 },
        "escalation_destination": { "$ref": "#/$defs/Did" },
        "scheduled_interval_hlc_units": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "claim_thresholds": { "type": "array", "items": { "$ref": "#/$defs/HashReference" } },
        "adverse_event_definitions": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "progressive_event_definitions": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
        "reporting_destinations": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "type": "string", "minLength": 1 } },
        "event_payload_type_domains": {
          "type": "array", "minItems": 4, "uniqueItems": true,
          "items": {
            "enum": [
              "exo.decision_forum.protocol_event.v1",
              "exo.decision_forum.estop_authorization.v1",
              "exo.decision_forum.capa_record.v1",
              "exo.decision_forum.reset_authorization.v1"
            ]
          }
        }
      }
    },
    "SystemicLearningManifest": {
      "type": "object",
      "additionalProperties": false,
      "required": ["records", "candidate_roadmap_scenarios", "authority_effect"],
      "properties": {
        "records": { "type": "array", "items": { "$ref": "#/$defs/SystemicLearningRecord" } },
        "candidate_roadmap_scenarios": { "type": "array", "items": { "$ref": "#/$defs/HashReference" } },
        "authority_effect": { "const": "ContextOnlyNoEnactmentAuthority" }
      }
    },
    "CommercialBoundary": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "core_license", "product_license_model", "bailment_licensure_hash",
        "permitted_use_hash", "metering_class", "usage_accounting_policy"
      ],
      "properties": {
        "core_license": { "const": "Apache-2.0" },
        "product_license_model": { "const": "commercial" },
        "bailment_licensure_hash": { "$ref": "#/$defs/Hash256" },
        "permitted_use_hash": { "$ref": "#/$defs/Hash256" },
        "metering_class": { "type": "string", "minLength": 1 },
        "usage_accounting_policy": { "const": "exo-economy-use-event-v1" }
      }
    },
    "CommitmentScheme": {
      "description": "AuthorizationTargetV1 includes protocol_identity, protocol_document, protocol_envelope, evidence_manifest, all review content, monitoring_plan, systemic_learning_manifest, commercial_boundary, preauthorization lifecycle receipts, the nonempty predecessor execution-chain reference for successor versions, and genesis adoption receipt. It excludes every current-version post-authorization action/event/continuing-review receipt, disposition_bundle, publication_authorization_receipt, and final_package_root. Current execution receipts live only in ProtocolExecutionReceiptChainV1 and reference an already-fixed package root. A successor package commits the preceding chain root.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "authorization_target_domain", "seat_attestation_signing_payload_domain",
        "peer_review_signing_payload_domain",
        "council_disposition_signing_payload_domain", "ai_irb_disposition_signing_payload_domain",
        "chair_intervention_signing_payload_domain", "prepublication_domain",
        "publication_authorization_domain", "final_package_domain",
        "artifact_manifest_domain", "execution_receipt_domain",
        "execution_receipt_chain_domain", "genesis_evidence_bundle_domain",
        "genesis_adoption_receipt_domain", "final_root_normalization"
      ],
      "properties": {
        "authorization_target_domain": { "const": "exo.decision_forum.protocol_authorization_target.v1" },
        "seat_attestation_signing_payload_domain": { "const": "exo.decision_forum.seat_attestation_signing_payload.v1" },
        "peer_review_signing_payload_domain": { "const": "exo.decision_forum.peer_review_signing_payload.v1" },
        "council_disposition_signing_payload_domain": { "const": "exo.decision_forum.council_disposition_signing_payload.v1" },
        "ai_irb_disposition_signing_payload_domain": { "const": "exo.decision_forum.ai_irb_disposition_signing_payload.v1" },
        "chair_intervention_signing_payload_domain": { "const": "exo.decision_forum.chair_intervention_signing_payload.v1" },
        "prepublication_domain": { "const": "exo.decision_forum.prepublication_package.v1" },
        "publication_authorization_domain": { "const": "exo.decision_forum.publication_authorization_receipt.v1" },
        "final_package_domain": { "const": "exo.decision_forum.peer_reviewed_protocol_package.v1" },
        "artifact_manifest_domain": { "const": "exo.decision_forum.publication_artifact_manifest.v1" },
        "execution_receipt_domain": { "const": "exo.decision_forum.protocol_execution_receipt.v1" },
        "execution_receipt_chain_domain": { "const": "exo.decision_forum.protocol_execution_receipt_chain.v1" },
        "genesis_evidence_bundle_domain": { "const": "exo.decision_forum.genesis_evidence_bundle.v1" },
        "genesis_adoption_receipt_domain": { "const": "exo.decision_forum.genesis_adoption_receipt.v1" },
        "final_root_normalization": { "const": "replace receipt_manifest.final_package_root with 32 zero bytes" }
      }
    },
    "PublisherAuthorityV1": {
      "type": "object",
      "additionalProperties": false,
      "required": ["publisher_did", "signing_key_id", "verification_key", "authority_chain_hash"],
      "properties": {
        "publisher_did": { "$ref": "#/$defs/Did" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "authority_chain_hash": { "$ref": "#/$defs/Hash256" }
      }
    },
    "PublicationAuthorizationReceipt": {
      "description": "In-package authorization for a pinned renderer. Its canonical signed body contains exactly prepublication_root, renderer_manifest_hash, publisher_did, and authorized_at; the signature key resolves to publisher_authority.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "prepublication_root", "renderer_manifest_hash", "publisher_did",
        "authorized_at", "publisher_authority", "signature"
      ],
      "properties": {
        "prepublication_root": { "$ref": "#/$defs/Hash256" },
        "renderer_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "publisher_did": { "$ref": "#/$defs/Did" },
        "authorized_at": { "$ref": "#/$defs/Timestamp" },
        "publisher_authority": { "$ref": "#/$defs/PublisherAuthorityV1" },
        "signature": { "$ref": "#/$defs/PublicationAuthorizationSignature" }
      }
    },
    "PreauthorizationLifecycleReceiptV1": {
      "description": "An in-package lifecycle receipt created no later than Approved. authorized_package_root is null because a current final root cannot be referenced before it exists.",
      "type": "object",
      "additionalProperties": false,
      "required": ["receipt_hash", "lifecycle_state", "authorized_package_root"],
      "properties": {
        "receipt_hash": { "$ref": "#/$defs/Hash256" },
        "lifecycle_state": {
          "enum": ["Draft", "Submitted", "IdentityResolved", "ConsentValidated", "Deliberated", "Verified", "Governed", "Approved"]
        },
        "authorized_package_root": { "type": "null" }
      }
    },
    "PriorExecutionReceiptChainReferenceV1": {
      "description": "A successor-package commitment to a nonempty execution/action/event/continuing-review chain whose authorized_package_root is the preceding package root, never the successor root.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "tenant_id", "protocol_id", "prior_protocol_version_hash",
        "authorized_package_root", "previous_chain_root",
        "predecessor_terminal_receipt_hash", "predecessor_terminal_sequence",
        "first_sequence", "chain_root", "terminal_receipt_hash",
        "terminal_sequence", "receipt_count"
      ],
      "properties": {
        "tenant_id": { "type": "string", "minLength": 1 },
        "protocol_id": { "type": "string", "minLength": 1 },
        "prior_protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "authorized_package_root": { "$ref": "#/$defs/Hash256" },
        "previous_chain_root": { "$ref": "#/$defs/Hash256" },
        "predecessor_terminal_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "predecessor_terminal_sequence": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "first_sequence": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "chain_root": { "$ref": "#/$defs/Hash256" },
        "terminal_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "terminal_sequence": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "receipt_count": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 }
      }
    },
    "ExecutionSignerAuthority": {
      "allOf": [
        { "$ref": "#/$defs/AuthorityChainReferenceV1" },
        { "properties": { "scope": { "const": "ProtocolExecutionReceiptV1" } } }
      ]
    },
    "ProtocolExecutionReceiptSignature": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "algorithm", "signing_key_id", "verification_key", "signature",
        "signed_payload_hash", "signed_payload_target"
      ],
      "properties": {
        "algorithm": { "const": "Ed25519" },
        "signing_key_id": { "$ref": "#/$defs/Hash256" },
        "verification_key": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "signature": { "type": "string", "pattern": "^[0-9a-f]{128}$" },
        "signed_payload_hash": { "$ref": "#/$defs/Hash256" },
        "signed_payload_target": { "const": "ProtocolExecutionReceiptV1" }
      }
    },
    "ProtocolExecutionReceipt": {
      "description": "External current-version signed receipt. Its canonical signing payload contains every field except signature and always names an already-fixed authorized package root.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "receipt_id", "tenant_id", "protocol_id", "protocol_version_hash",
        "authorized_package_root", "sequence", "receipt_kind",
        "previous_receipt_hash", "payload_hash", "idempotency_key_hash",
        "occurred_at", "signer_did", "signature"
      ],
      "properties": {
        "receipt_id": { "$ref": "#/$defs/Uuid" },
        "tenant_id": { "type": "string", "minLength": 1 },
        "protocol_id": { "type": "string", "minLength": 1 },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "authorized_package_root": { "$ref": "#/$defs/Hash256" },
        "sequence": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "receipt_kind": {
          "enum": [
            "ActionExecuted", "ContinuingReview", "ProgressiveEvent", "AdverseEvent",
            "AiSdlcTransgression", "Estop", "Capa", "Reset", "Closeout"
          ]
        },
        "previous_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "payload_hash": { "$ref": "#/$defs/Hash256" },
        "idempotency_key_hash": { "$ref": "#/$defs/Hash256" },
        "occurred_at": { "$ref": "#/$defs/Timestamp" },
        "signer_did": { "$ref": "#/$defs/Did" },
        "signature": { "$ref": "#/$defs/ProtocolExecutionReceiptSignature" }
      }
    },
    "ProtocolExecutionReceiptChainV1": {
      "description": "External nonempty current-version chain. It is never embedded in the package whose root its receipts authorize; only a successor package commits its chain root.",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schema_version", "tenant_id", "protocol_id", "protocol_version_hash",
        "authorized_package_root", "previous_chain_root",
        "predecessor_terminal_receipt_hash", "predecessor_terminal_sequence",
        "first_sequence", "signer_authorities", "receipts",
        "terminal_receipt_hash", "terminal_sequence", "receipt_count", "chain_root"
      ],
      "properties": {
        "schema_version": { "const": 1 },
        "tenant_id": { "type": "string", "minLength": 1 },
        "protocol_id": { "type": "string", "minLength": 1 },
        "protocol_version_hash": { "$ref": "#/$defs/Hash256" },
        "authorized_package_root": { "$ref": "#/$defs/Hash256" },
        "previous_chain_root": { "$ref": "#/$defs/Hash256" },
        "predecessor_terminal_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "predecessor_terminal_sequence": { "type": "integer", "minimum": 0, "maximum": 18446744073709551615 },
        "first_sequence": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "signer_authorities": {
          "type": "object", "minProperties": 1,
          "propertyNames": { "pattern": "^did:exo:[A-Za-z0-9_:-]+$" },
          "additionalProperties": { "$ref": "#/$defs/ExecutionSignerAuthority" }
        },
        "receipts": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/ProtocolExecutionReceipt" } },
        "terminal_receipt_hash": { "$ref": "#/$defs/Hash256" },
        "terminal_sequence": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "receipt_count": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
        "chain_root": { "$ref": "#/$defs/Hash256" }
      }
    },
    "DeterministicArtifactManifestV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "final_package_root", "renderer_manifest_hash", "canonical_cbor_digest",
        "markdown_digest", "html_digest", "pdf_a_digest"
      ],
      "properties": {
        "final_package_root": { "$ref": "#/$defs/Hash256" },
        "renderer_manifest_hash": { "$ref": "#/$defs/Hash256" },
        "canonical_cbor_digest": { "$ref": "#/$defs/Hash256" },
        "markdown_digest": { "$ref": "#/$defs/Hash256" },
        "html_digest": { "$ref": "#/$defs/Hash256" },
        "pdf_a_digest": { "$ref": "#/$defs/Hash256" }
      }
    },
    "ReceiptManifest": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "commitment_scheme", "preauthorization_lifecycle_receipts",
        "prior_execution_receipt_chain", "publication_authorization_receipt",
        "genesis_adoption_receipt",
        "final_package_root"
      ],
      "properties": {
        "commitment_scheme": { "$ref": "#/$defs/CommitmentScheme" },
        "preauthorization_lifecycle_receipts": {
          "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/PreauthorizationLifecycleReceiptV1" }
        },
        "prior_execution_receipt_chain": {
          "oneOf": [{ "$ref": "#/$defs/PriorExecutionReceiptChainReferenceV1" }, { "type": "null" }]
        },
        "publication_authorization_receipt": { "$ref": "#/$defs/PublicationAuthorizationReceipt" },
        "genesis_adoption_receipt": {
          "oneOf": [{ "$ref": "#/$defs/GenesisAdoptionReceipt" }, { "type": "null" }]
        },
        "final_package_root": { "$ref": "#/$defs/Hash256" }
      }
    }
  }
}
```

- [ ] **Step 4: Run GREEN and validate the JSON independently**

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract normative_schema_fixes_package_components_and_deterministic_primitives -- --exact --nocapture
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract commitment_construction_is_acyclic_and_mutation_complete -- --exact --nocapture
jq -e '.title == "PeerReviewedProtocolPackageV1" and .properties.schema_version.const == 1' governance/schemas/peer-reviewed-protocol-package-v1.schema.json
schema=governance/schemas/peer-reviewed-protocol-package-v1.schema.json
jq -e '
  (.["$defs"].EvidenceClass.enum | index("ProviderModelJudgment")) != null and
  (.["$defs"].IndependentEvidenceClass.enum | index("ProviderModelJudgment")) == null and
  .["$defs"].EvidenceManifest.properties.independent_evidence_classes.items."$ref" == "#/$defs/IndependentEvidenceClass" and
  .["$defs"].QuorumProof.properties.evidence_classes.items."$ref" == "#/$defs/IndependentEvidenceClass" and
  .["$defs"].EstopAuthorization.properties.independent_evidence_classes.items."$ref" == "#/$defs/IndependentEvidenceClass"
' "$schema"
rg -n 'ProviderModelJudgment cannot satisfy an independent evidence floor|provider_judgment_floor|IndependentEvidenceClass' crates/decision-forum/tests/df_protocol_001_normative_contract.rs
rg -n 'VerifiedSeatAuthorityRegistryV1|SeatAttestationSigningPayloadV1|fully_resign_with_untrusted_seat_keys' crates/decision-forum/tests/df_protocol_001_normative_contract.rs
! rg -n 'trusted_(signing_)?authority_by_seat.*(attestation|roster)|from_(attestation|roster).*VerifiedSeatAuthority' crates/decision-forum/src crates/decision-forum/tests
```

Expected: both commands `PASS`/exit 0. The Rust test compiles the document with
the pinned validator under `Draft::Draft202012`, validates the complete
positive binding package (including HLC zero and a typed SHA-1 Git object ID),
validates controller-signed `SeatAttestationSigningPayloadV1` plus real Ed25519
`PeerReviewV1`, `CouncilDispositionV1`,
`AiIrbDispositionV1`, and publication-authorization envelopes over their exact
domain-separated bodies. It resolves all ten review/vote keys only through the
independently produced opaque `VerifiedSeatAuthorityRegistryV1`, matches every
package attestation and typed authority-chain reference to that registry, and
resolves Chair/publisher keys through `VerifiedAuthorityRegistryV1`. It proves
exactly ten assignments and ten signed
reviews cover the five Council plus five AI-IRB roles exactly once; exactly two
five-of-five eligible-unanimity proofs cover those bodies with the provider and
independent-evidence floors. The binding manifest, both quorum proofs, and
E-STOP threshold use the closed `IndependentEvidenceClass`, while the broader
`EvidenceClass` retains `ProviderModelJudgment` only for non-binding inventory.
The adversarial probe substitutes the exact formerly accepted pair
`[ProviderModelJudgment, IndependentNonProviderEvidence]`, re-signs and rehashes
the package and both quorum proofs, and proves that neither schema nor semantic
validation can produce `VerifiedPackageRoot` or authorize an execution chain.
It also rejects missing, duplicate, wrong-role, wrong-key, wrong-context,
wrong-body, counterfeit-quorum, non-Approve, roster-shrinkage, Chair/dissent
mismatch, noncanonical UUID, and Git-object-ID confusion cases.
The full trust-anchor substitution test replaces all ten seat keypairs,
controller-re-signs all ten attestations, re-signs all reviews and votes,
recomputes assignments, quorum proofs, the authorization target, Chair and
publication receipts, authority-chain references, and final root, while
leaving the trusted registry unchanged; semantic verification must reject it.
Focused cases also reject one-seat substitution after controller re-sign,
controller-signature mutation, seat authority-chain mismatch, expired seat
authority, and not-yet-valid seat authority. The final negative `rg` is a
source guard: no implementation or test helper may construct a trusted seat
registry or trusted review/vote key map from a package roster or attestation.
The commitment test proves predecessor-only in-package lifecycle receipt
commitments, an external signed current-version execution chain that binds the
already-fixed package root, successor commitment to that prior chain, exact
publication/final-root normalization, replay/link rejection, and complete
mutation behavior for every authoritative package, review, vote, signature,
quorum, receipt-chain, renderer, evidence, and prior-version field.

The two seat-attestation collections are closed five-property objects keyed by
the four provider-class labels and `independent_non_provider`; every value
carries the actual seat DID. The semantic guard proves exact set equality among
roster DIDs, eligible DIDs, vote DIDs, and assignments and proves body-specific
keys and context manifests are disjoint. Slice 4's HTTP JSON decoder must
reject duplicate object member names before schema validation; a
last-member-wins parser is not an acceptable substitute for this normative map
contract.

- [ ] **Step 5: Commit the reviewed schema and guard**

```bash
git add Cargo.lock crates/decision-forum/Cargo.toml crates/decision-forum/tests/df_protocol_001_normative_contract.rs governance/schemas/peer-reviewed-protocol-package-v1.schema.json
git commit -m "docs(governance): define peer-reviewed package schema"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

### Task 3: Content-address the proposal without claiming ratification

**Files:**

- Modify: `crates/decision-forum/tests/df_protocol_001_normative_contract.rs`
- Create: `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json`

**Interfaces:**

- Consumes: exact Amendment 1 bytes from Task 1.
- Produces: machine-checkable predecessor/amendment linkage and explicit
  fail-closed ratification/credential state.

- [ ] **Step 1: Add the failing manifest test**

Append:

```rust
#[test]
fn amendment_manifest_binds_exact_bytes_without_enactment() {
    let amendment_path = "governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md";
    let amendment = read_bytes(amendment_path);
    let manifest_text =
        read_text("governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_text).expect("amendment manifest must be valid JSON");

    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["proposal_id"], "D9-COUNCIL-CHARTER-AMENDMENT-1");
    assert_eq!(manifest["proposal_status"], "proposed");
    assert_eq!(manifest["binding_mode_allowed"], false);
    assert_eq!(manifest["predecessor"]["blake3"], FROZEN_D9_BLAKE3);
    assert_eq!(manifest["amendment"]["blake3"], AMENDMENT_1_BLAKE3);
    assert_eq!(
        blake3::hash(&amendment).to_hex().as_str(),
        AMENDMENT_1_BLAKE3
    );
    assert_eq!(
        manifest["design_commit"],
        "23742d90ad4f08f62a668ca7b371b9e318177885"
    );
    assert_eq!(
        manifest["ratification_receipt_hashes"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        manifest["credential_attestation_hashes"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
}
```

- [ ] **Step 2: Run the guard and capture RED**

Run:

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract amendment_manifest_binds_exact_bytes_without_enactment -- --exact --nocapture
```

Expected: `FAIL` because the manifest file does not exist.

- [ ] **Step 3: Compute the exact amendment digest and create the manifest**

Run `b3sum governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md`. The exact
Task 1 bytes must produce
`38330feabc0d18c5d00eb7268631c6d92dc608118f465fc84e07871bd7217c81`.
If they do not, stop and correct the file to the reviewed Task 1 bytes before
creating the manifest. Do not normalize, re-render, or edit the amendment
between hashing and commit. Create the manifest with these exact fields:

```json
{
  "amendment": {
    "blake3": "38330feabc0d18c5d00eb7268631c6d92dc608118f465fc84e07871bd7217c81",
    "path": "governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md"
  },
  "binding_mode_allowed": false,
  "credential_attestation_hashes": [],
  "design_commit": "23742d90ad4f08f62a668ca7b371b9e318177885",
  "predecessor": {
    "blake3": "c1e89db47a30849d41e6db9c4c23d52d9dfbf3a820f2695dcdbcade6d42bd6af",
    "path": "governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md"
  },
  "proposal_id": "D9-COUNCIL-CHARTER-AMENDMENT-1",
  "proposal_status": "proposed",
  "ratification_receipt_hashes": [],
  "schema_version": 1
}
```

The implementer report must record the exact `b3sum` command and matching
output.

- [ ] **Step 4: Run GREEN and re-check both proposal hashes**

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract amendment_manifest_binds_exact_bytes_without_enactment -- --exact --nocapture
b3sum governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md
```

Expected: test `PASS`; predecessor hash exactly matches the fixed digest; the
amendment hash exactly matches the manifest.

- [ ] **Step 5: Commit the content-addressed manifest**

```bash
git add crates/decision-forum/tests/df_protocol_001_normative_contract.rs governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json
git commit -m "docs(governance): bind D9 amendment manifest"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

### Task 4: Register threat and acceptance traceability without overclaiming

**Files:**

- Modify: `crates/decision-forum/tests/df_protocol_001_normative_contract.rs`
- Modify: `governance/threat_matrix.md`
- Modify: `governance/traceability_matrix.md`

**Interfaces:**

- Consumes: design acceptance criteria 1-20 and slice dependency map.
- Produces: stable threat IDs `T-18` through `T-25` and requirement IDs
  `DF-001` through `DF-020` used in later tests and PR evidence.

- [ ] **Step 1: Add the failing matrix guard**

Append:

```rust
#[test]
fn threat_and_traceability_matrices_cover_df_protocol_001() {
    let threats = read_text("governance/threat_matrix.md");
    for threat_id in [
        "T-18", "T-19", "T-20", "T-21", "T-22", "T-23", "T-24", "T-25",
    ] {
        assert!(threats.contains(threat_id), "missing {threat_id}");
    }

    let traceability = read_text("governance/traceability_matrix.md");
    for requirement_number in 1..=20 {
        let requirement_id = format!("DF-{requirement_number:03}");
        assert!(
            traceability.contains(&requirement_id),
            "missing {requirement_id}"
        );
    }
    for (requirement_id, exact_owner) in [
        ("DF-001", "Slices 2, 5, 10"),
        ("DF-002", "Slices 2 and 5"),
        ("DF-003", "Slices 1 and 3"),
        ("DF-004", "Slices 1 and 3"),
        ("DF-005", "Slices 1, 3, and 4"),
        ("DF-006", "Slices 1, 3, and 4"),
        ("DF-007", "Slices 1, 3, and 4"),
        ("DF-008", "Slices 1, 3, and 4"),
        ("DF-009", "Slices 3, 4, 6, and 7"),
        ("DF-010", "Slices 2, 3, 4, 6, and 7"),
        ("DF-011", "Slices 4 and 7"),
        ("DF-012", "Slices 4 and 6"),
        ("DF-013", "Slices 2, 3, 4, 6"),
        ("DF-014", "Slices 1, 6, 7, 8, 10"),
        ("DF-015", "Slices 9 and 10"),
        ("DF-016", "Every slice"),
        ("DF-017", "Slices 4, 5, 6"),
        ("DF-018", "Slice 4"),
        ("DF-019", "Slices 4 and 10"),
        ("DF-020", "Slices 1, 4, 9"),
    ] {
        let row = traceability
            .lines()
            .find(|line| line.contains(requirement_id))
            .unwrap_or_else(|| panic!("missing traceability row {requirement_id}"));
        assert!(
            row.contains(exact_owner),
            "{requirement_id} owner drift: expected {exact_owner}, row was {row}"
        );
    }
    assert_contains_all(
        &traceability,
        &[
            "DF-PROTOCOL-001",
            "Specified; enforcement evidence assigned to slice",
            "No DAG DB retrieval-quality or economic-thesis dependency",
            "| **TOTAL** | **139** | **114** | **23** | **2** |",
            "Coverage: 114/139 requirements implemented (82%)",
        ],
    );
}
```

- [ ] **Step 2: Run the matrix guard and capture RED**

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract threat_and_traceability_matrices_cover_df_protocol_001 -- --exact --nocapture
```

Expected: `FAIL` with `missing T-18`.

- [ ] **Step 3: Extend the threat matrix with exact non-green rows**

Add these rows after `T-17`. Preserve the current implemented rows. Mark each
new row `🟡 Specified; enforcement evidence assigned to slice N`, never green:

```markdown
| **T-18** | **Unratified Binding-Mode Activation** | A runtime, administrator, or mutable projection could treat advisory Council/AI-IRB output as binding without the exact authenticated D9 Amendment 1 hash. Mitigation contract: immutable predecessor/amendment linkage, ratification receipt verification, credential attestations, kernel check, and default-deny binding mode. | `governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1*`; enforcement assigned to slices 2-4 | Unratified/advisory negative tests; wrong-hash, absent-receipt, and mutable-projection bypass tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **T-19** | **Seat Laundering and Denominator Shrinkage** | Authors, Co-PIs, correlated sessions, expired or conflicted seats, provider prose, recusals, or unavailability could be used to counterfeit independence or lower eligible unanimity. Mitigation contract: separately attested Council/AI-IRB seats, fixed five-seat rosters, four-provider floor, two-evidence-class floor including non-provider evidence, no self-review, and no silent denominator change. | Schema and Amendment 1; enforcement assigned to slice 3 | Self-review, common-control, changed-model, missing/recused/expired/conflicted seat, provider/evidence-floor tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **T-20** | **Package, Vote, and Publication Divergence** | A detached vote, mutable status, changed document, renderer drift, or replaced publication could authorize bytes reviewers never approved. Mitigation contract: package-hash-bound actions, canonical CBOR authority, immutable review/disposition evidence, hermetic projections, and manifest verification. | Schema; enforcement assigned to slices 2, 4, and 5 | Byte mutation matrix and clean-run CBOR/Markdown/HTML/PDF-A reproducibility tests | 🟡 Specified; enforcement evidence assigned to slice 5 |
| **T-21** | **Stop, CAPA, or RESET Bypass** | REST, GraphQL, SDK, MCP, replay, duplicate idempotency keys, sibling routes, or projection edits could execute a stopped protocol or clear an event without required human and unanimous evidence. Mitigation contract: scoped holds, threshold E-STOP, immutable event chain, human-attested AAR/RCA, CAPA, recurrence, dual eligible unanimity, Chair signature, and new version/hash. | Amendment 1; enforcement assigned to slices 3 and 4 | Stop ingress matrix and missing-reset-precondition tests | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **T-22** | **Projection/Receipt Split and Cross-Tenant Replay** | A projection could commit without its DAG DB receipt, a receipt could commit without its projection, or stale/cross-tenant heads could be accepted. Mitigation contract: one transaction in `dagdb`, RLS tenant binding, idempotency/body binding, compare-and-set receipt heads, outbox/recovery, exact reconstruction, and no fallback store. | Amendment 1; enforcement assigned to slice 4 | Forced rollback on both sides, RLS, stale head, body conflict, broken chain, reconstruction, and cross-tenant tests | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **T-23** | **Blind-Custody Identity Leak or Authority Escalation** | CrossChecked or a local cache could reveal identities early, vote, authorize, hold core signing keys, originate receipts, or weaken review during outage. Mitigation contract: commitment-before-reveal, sealed metadata, core verification, separate credentials/licensure/accounting, and fail-closed required blinding. | Amendment 1; enforcement assigned to slices 3, 4, 6, and 7 | Early-reveal, invalid commitment, outage, unlicensed adapter, attempted vote/receipt/key authority tests | 🟡 Specified; enforcement evidence assigned to slice 7 |
| **T-24** | **Nondeterministic Governance or Publication** | Floating point, unordered collections, wall clock, random IDs, direct JSON hashing, network resources, font drift, or renderer metadata could change authoritative bytes. Mitigation contract: integers/basis points, ordered collections, caller IDs, HLC, canonical CBOR, pinned hermetic renderer, and repeated clean-run digests. | Schema; enforcement assigned to slices 2 and 5 | Source guards and cross-platform/repeated-clean-run reproducibility tests | 🟡 Specified; enforcement evidence assigned to slice 5 |
| **T-25** | **Adjacent License or Trust Claim by Proximity** | Commercial Decision Forum, CrossChecked, CyberMedica, LegalDyne, or LiveSafe code could inherit Apache terms, core secrets, or constitutional claims without a tested core path. Mitigation contract: path classification, intake records, commercial registry, isolated secrets, licensure/accounting, fail-closed adapters, and separate commits/PRs. | `governance/commercial-product-licensing.json`; enforcement assigned to slices 6-8 | SPDX/package/source/license guards, intake checks, secret-scope and core-regression tests | 🟡 Specified; enforcement evidence assigned to slice 6 |
```

Update the threat summary to 17 implemented and 8 specified/partial threats;
do not convert any new row to implemented based on the proposal or schema.

- [ ] **Step 4: Add the complete acceptance traceability section**

Add a `## DF-PROTOCOL-001 Peer-Reviewed Protocol Governance` section before
the existing summary in `governance/traceability_matrix.md` with these rows:

```markdown
| Req | Requirement | Owning slice and acceptance evidence | Status |
|---|---|---|---|
| **DF-001** | Identical package input yields identical canonical CBOR, Markdown, HTML, PDF/A, and receipt roots | Slices 2, 5, 10; canonical-byte and clean-run renderer digest tests | 🟡 Specified; enforcement evidence assigned to slice 2 |
| **DF-002** | Any authoritative byte/review/vote/evidence/receipt/renderer/prior-link change changes commitment or fails verification | Slices 2 and 5; mutation matrix | 🟡 Specified; enforcement evidence assigned to slice 2 |
| **DF-003** | Author or Co-PI cannot satisfy independent review | Slices 1 and 3; amendment/schema rule plus self-review/common-controller denial tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-004** | Missing, recused, expired, changed, or conflicted seats cannot lower denominator/evidence floor | Slices 1 and 3; normative roster floor plus eligible-set adversarial matrix | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-005** | Authorization dissent blocks unanimity; monitoring dissent alerts Chair without manufacturing E-STOP | Slices 1, 3, and 4; typed dissent decisions, Chair alert receipt, and authorization denial tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-006** | Kernel denial, Chair hold, and threshold E-STOP have distinct effects | Slices 1, 3, and 4; authority-state transition and sibling-ingress tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-007** | Progressive promotion cannot escape phase ladder or envelope | Slices 1, 3, and 4; envelope subset and boundary tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-008** | RESET requires human AAR/RCA, CAPA, recurrence, Council unanimity, AI-IRB unanimity, and Chair signature | Slices 1, 3, and 4; human AAR/RCA, CAPA, recurrence, dual-unanimity, and Chair-signature tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-009** | Stopped protocol cannot execute through REST, GraphQL, SDK, MCP, replay, duplicate idempotency, sibling, or cross-tenant ingress | Slices 3, 4, 6, and 7; REST/GraphQL/SDK/MCP/replay/idempotency/cross-tenant bypass matrix | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **DF-010** | Blind identity/provider/arm metadata stays sealed until commitments fix; reveal matches commitments | Slices 2, 3, 4, 6, and 7; cryptographic commitment/reveal and UI disclosure tests | 🟡 Specified; enforcement evidence assigned to slice 7 |
| **DF-011** | CrossChecked outage/invalid proof fails closed without evidence loss or core weakening | Slices 4 and 7; outage/retention tests | 🟡 Specified; enforcement evidence assigned to slice 7 |
| **DF-012** | UI uses authenticated identities and exact Rust states; local wall-clock/random records are nonauthoritative | Slices 4 and 6; generated-contract, source-guard, and browser tests | 🟡 Specified; enforcement evidence assigned to slice 6 |
| **DF-013** | AI-SDLC transgressions create mandatory receipts, alerts, containment, and disposition | Slices 2, 3, 4, 6; event/notification tests | 🟡 Specified; enforcement evidence assigned to slice 3 |
| **DF-014** | Apache core and commercial product licenses/attribution remain separated | Slices 1, 6, 7, 8, 10; license registry and source/package guards | 🟡 Specified; enforcement evidence assigned to slice 1 |
| **DF-015** | Dogfood task matrix publishes raw references, exclusions, failures, identities, prompts, costs, disagreements, and audit results without synthetic substitution | Slices 9 and 10; evidence-manifest reproducibility tests | 🟡 Specified; enforcement evidence assigned to slice 9 |
| **DF-016** | Full Rust, TypeScript, database, security, release-boundary, documentation, license, and cross-implementation gates pass cleanly | Every slice; final clean-checkout gate record in slice 10 | 🟡 Specified; enforcement evidence assigned to slice 10 |
| **DF-017** | DAG DB unavailable/degraded denies governed mutation and authoritative mutable read; verified static publication is visibly degraded | Slices 4, 5, 6; failure-injection and public-label tests | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **DF-018** | Projection and DAG DB receipt commit atomically; forced failure leaves neither side changed | Slice 4; transaction rollback tests | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **DF-019** | Reconstruction returns exact ordered history and rejects replay conflict, stale head, broken link, and cross-tenant read | Slices 4 and 10; live Postgres reconstruction tests | 🟡 Specified; enforcement evidence assigned to slice 4 |
| **DF-020** | No DAG DB retrieval-quality or economic-thesis dependency | Slices 1, 4, 9; dependency/source/test inventory guards and `DF-ROADMAP-001` isolation | 🟡 Specified; enforcement evidence assigned to slice 1 |
```

Add a summary category row `DF-PROTOCOL-001 | 20 | 0 | 20 | 0`, change the
grand total to `139 | 114 | 23 | 2`, and change the prose coverage calculation
to `114/139 requirements implemented (82%)`. Preserve the 3 existing partial
ZK rows and 2 existing planned monitoring rows; the new 20 rows are yellow,
not implemented.

- [ ] **Step 5: Run GREEN and focused documentation guards**

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract threat_and_traceability_matrices_cover_df_protocol_001 -- --exact --nocapture
bash tools/test_proprietary_license_boundaries.sh
TASK_BASE="$(tr -d '\n' < .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha)"
git cat-file -e "$TASK_BASE^{commit}"
git diff --check "$TASK_BASE"
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit threat and traceability records**

```bash
git add crates/decision-forum/tests/df_protocol_001_normative_contract.rs governance/threat_matrix.md governance/traceability_matrix.md
git commit -m "docs(governance): trace DF protocol threats"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

### Task 5: Harden the canonical cross-implementation gate to compare real outputs

**Files:**

- Modify: `tools/cross-impl-test/compare.sh`
- Modify: `tools/cross-impl-test/compare_unit_test.sh`
- Delete: `tools/cross-impl-test/index.js`
- Create: `tools/cross-impl-test/index.ts`
- Modify: `tools/cross-impl-test/package.json`
- Modify: `tools/cross-impl-test/package-lock.json`
- Create: `tools/cross-impl-test/tsconfig.json`
- Create: `tools/cross-impl-test/vectors/hash_blake3.json`
- Modify: `crates/exo-core/tests/cross_impl_hash_vectors.rs`

**Interfaces:**

- Consumes: the existing canonical `tools/cross-impl-test` harness and
  `exo_core::hash::canonical_hash`; it does not call the unrelated
  `/Users/bobstewart/dev/demo/exo` test suite.
- Produces: two normalized JSONL files with one actual result per committed
  vector and an exact `diff` gate. A skip, unsupported vector, duplicate ID,
  expected-digest mismatch, missing output, or Rust/TypeScript divergence is a
  nonzero result.

- [ ] **Step 1: Add the failing real-output regression guard**

Replace `tools/cross-impl-test/compare_unit_test.sh` with the existing Apache
header followed by this exact test body before changing any runner:

```bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/compare.sh"

TMP_DIR="$(mktemp -d /tmp/exochain-cross-impl-unit.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

declare -F compare_vector_outputs >/dev/null
declare -F prepare_typescript_executor >/dev/null
declare -F run_typescript_vectors >/dev/null

cat > "$TMP_DIR/rust.jsonl" <<'EOF'
{"actual":{"blake3_hex":"74a1c68dabb660207c842b9b7dd0953a6a8e8158bb397c5bd4ea9fceda0c4c96"},"category":"crypto_hash","name":"BLAKE3 hash of canonical CBOR","vector_id":"hash_blake3"}
EOF
cat > "$TMP_DIR/typescript.jsonl" <<'EOF'
{"actual":{"blake3_hex":"0000000000000000000000000000000000000000000000000000000000000000"},"category":"crypto_hash","name":"BLAKE3 hash of canonical CBOR","vector_id":"hash_blake3"}
EOF
if compare_vector_outputs "$TMP_DIR/rust.jsonl" "$TMP_DIR/typescript.jsonl" 1; then
  echo "mismatched TypeScript actual output passed" >&2
  exit 1
fi

mkdir "$TMP_DIR/bad-vectors"
cp "$SCRIPT_DIR/vectors/hash_blake3.json" "$TMP_DIR/bad-vectors/hash_blake3.json"
jq '.expected.blake3_hex = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$TMP_DIR/bad-vectors/hash_blake3.json" > "$TMP_DIR/bad-vectors/vector.tmp"
mv "$TMP_DIR/bad-vectors/vector.tmp" "$TMP_DIR/bad-vectors/hash_blake3.json"
prepare_typescript_executor "$TMP_DIR/typescript-executor"
if run_typescript_vectors "$TMP_DIR/typescript-executor" \
    "$TMP_DIR/bad-vectors" "$TMP_DIR/bad-ts.jsonl"; then
  echo "bad vector unexpectedly passed TypeScript execution" >&2
  exit 1
fi

if rg -n 'EXO_TS_ROOT|--exo-ts-root|create_default_vectors|pass_count|RESULTS_DIR="\$SCRIPT_DIR/results"' \
  "$SCRIPT_DIR/compare.sh"; then
  echo "cross-implementation gate still permits skip/count/repository residue paths" >&2
  exit 1
fi
if rg -n '\(cd "\$SCRIPT_DIR".*(npm ci|npm install|npm run|npx)' \
  "$SCRIPT_DIR/compare.sh"; then
  echo "cross-implementation gate executes the TypeScript toolchain in the repository" >&2
  exit 1
fi
test ! -d "$SCRIPT_DIR/node_modules"
```

Run:

```bash
bash tools/cross-impl-test/compare_unit_test.sh
```

Expected RED: nonzero with `compare_vector_outputs` missing. The current
`compare.sh` also contains the prohibited external-root, pass-count, generated
vector, and repository-results paths. A pass is invalid RED evidence.

- [ ] **Step 2: Commit one real vector and replace the JavaScript runner with TypeScript**

Create `tools/cross-impl-test/vectors/hash_blake3.json`:

```json
{
  "vector_id": "hash_blake3",
  "name": "BLAKE3 hash of canonical CBOR",
  "category": "crypto_hash",
  "input": { "canonical_cbor_hex": "a1616101" },
  "expected": {
    "blake3_hex": "74a1c68dabb660207c842b9b7dd0953a6a8e8158bb397c5bd4ea9fceda0c4c96"
  }
}
```

Delete `tools/cross-impl-test/index.js` and create
`tools/cross-impl-test/index.ts` with the existing Apache header plus:

```typescript
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { hash } from 'blake3';

type HashVector = {
  vector_id: string;
  name: string;
  category: 'crypto_hash';
  input: { canonical_cbor_hex: string };
  expected: { blake3_hex: string };
};

type VectorResult = {
  vector_id: string;
  name: string;
  category: 'crypto_hash';
  actual: { blake3_hex: string };
};

function option(name: string): string {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) {
    throw new Error(`missing ${name}`);
  }
  return process.argv[index + 1];
}

function decodeHex(value: string, label: string): Buffer {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${label}: canonical_cbor_hex must be lowercase even-length hex`);
  }
  return Buffer.from(value, 'hex');
}

const vectorsDir = option('--vectors');
const output = option('--output');
const files = readdirSync(vectorsDir).filter((file) => file.endsWith('.json')).sort();
if (files.length === 0) throw new Error('no committed vectors');

const results: VectorResult[] = files.map((file) => {
  const path = join(vectorsDir, file);
  const vector = JSON.parse(readFileSync(path, 'utf8')) as HashVector;
  if (vector.category !== 'crypto_hash' || vector.vector_id !== basename(file, '.json')) {
    throw new Error(`${file}: unsupported category or vector_id/file mismatch`);
  }
  const actual = hash(decodeHex(vector.input.canonical_cbor_hex, file)).toString('hex');
  if (actual !== vector.expected.blake3_hex) {
    throw new Error(`${file}: expected ${vector.expected.blake3_hex}, got ${actual}`);
  }
  return {
    vector_id: vector.vector_id,
    name: vector.name,
    category: vector.category,
    actual: { blake3_hex: actual },
  };
});

writeFileSync(
  output,
  `${results.sort((a, b) => a.vector_id.localeCompare(b.vector_id))
    .map((result) => JSON.stringify(result)).join('\n')}\n`,
  { flag: 'wx' },
);
```

Replace `tools/cross-impl-test/package.json` with:

```json
{
  "name": "exochain-cross-impl-test",
  "version": "1.0.0",
  "private": true,
  "description": "Cross-implementation test vectors for EXOCHAIN",
  "scripts": {
    "test": "bash compare_unit_test.sh",
    "typecheck": "tsc --noEmit",
    "vectors": "tsx index.ts"
  },
  "dependencies": { "blake3": "2.1.7" },
  "devDependencies": {
    "@types/node": "22.10.2",
    "tsx": "4.19.2",
    "typescript": "5.7.2"
  }
}
```

Create `tools/cross-impl-test/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noEmit": true,
    "types": ["node"]
  },
  "include": ["index.ts"]
}
```

Regenerate only the tracked lockfile in place. This is the sole permitted npm
operation in the repository source directory and it uses
`--package-lock-only`, so it cannot install a dependency tree. Copy the
reviewed package, updated lock, source, and compiler contract into a temporary
executor, then perform every install and typecheck there:

```bash
(
  cd tools/cross-impl-test
  npm install --package-lock-only --ignore-scripts
)
TEMP_EXECUTOR="$(mktemp -d /tmp/exochain-cross-impl-lock-check.XXXXXX)"
cleanup_temp_executor() { rm -rf "$TEMP_EXECUTOR"; }
trap cleanup_temp_executor EXIT
cp tools/cross-impl-test/package.json \
  tools/cross-impl-test/package-lock.json \
  tools/cross-impl-test/index.ts \
  tools/cross-impl-test/tsconfig.json \
  "$TEMP_EXECUTOR/"
(
  cd "$TEMP_EXECUTOR"
  npm ci
  npm run typecheck
)
test ! -d tools/cross-impl-test/node_modules
cleanup_temp_executor
trap - EXIT
```

Expected: lockfile update succeeds, the clean install and TypeScript typecheck
exit 0 inside the temporary executor, the trap removes that executor, and no
repository-local `node_modules` is created.

- [ ] **Step 3: Make the Rust executor emit the same actual result records**

Replace `crates/exo-core/tests/cross_impl_hash_vectors.rs` with the existing
Apache header followed by this exact implementation:

```rust
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use exo_core::hash::canonical_hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct HashVector {
    vector_id: String,
    name: String,
    category: String,
    input: HashVectorInput,
    expected: HashVectorExpected,
}

#[derive(Debug, Deserialize)]
struct HashVectorInput {
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct HashVectorExpected {
    blake3_hex: String,
}

#[derive(Debug, Serialize)]
struct VectorResult {
    vector_id: String,
    name: String,
    category: String,
    actual: ActualHash,
}

#[derive(Debug, Serialize)]
struct ActualHash {
    blake3_hex: String,
}

#[test]
fn cross_impl_hash_vectors_match_golden() -> Result<(), Box<dyn std::error::Error>> {
    let vectors_dir = env::var_os("EXOCHAIN_CROSS_IMPL_HASH_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/cross-impl-test/vectors")
        });
    let mut files = fs::read_dir(&vectors_dir)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?;
    files.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    files.sort();
    if files.is_empty() {
        return Err("no committed cross-implementation vectors".into());
    }

    let mut results = Vec::new();
    for file in files {
        let vector: HashVector = serde_json::from_str(&fs::read_to_string(&file)?)?;
        if vector.category != "crypto_hash"
            || file.file_stem().and_then(|value| value.to_str()) != Some(&vector.vector_id)
        {
            return Err(format!(
                "{}: unsupported category or vector_id/file mismatch",
                file.display()
            )
            .into());
        }
        let actual =
            canonical_hash(&decode_hex(&vector.input.canonical_cbor_hex, &file)?).to_string();
        if actual != vector.expected.blake3_hex {
            return Err(format!(
                "{}: expected {}, got {actual}",
                file.display(),
                vector.expected.blake3_hex
            )
            .into());
        }
        results.push(VectorResult {
            vector_id: vector.vector_id,
            name: vector.name,
            category: vector.category,
            actual: ActualHash { blake3_hex: actual },
        });
    }
    results.sort_by(|left, right| left.vector_id.cmp(&right.vector_id));
    if let Some(output) = env::var_os("EXOCHAIN_CROSS_IMPL_OUTPUT") {
        let body = results
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n")
            + "\n";
        fs::write(PathBuf::from(output), body)?;
    }
    Ok(())
}

fn decode_hex(hex: &str, file: &Path) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{}: canonical_cbor_hex must be lowercase even-length hex",
            file.display()
        ));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}
```

- [ ] **Step 4: Replace blind counts and repository-local results with exact comparison**

Replace `tools/cross-impl-test/compare.sh` with the existing Apache header
followed by this exact implementation:

```bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXOCHAIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

compare_vector_outputs() {
  local rust_output="$1" ts_output="$2" expected_count="$3"
  local rust_normalized ts_normalized
  rust_normalized="$(mktemp /tmp/exochain-rust-normalized.XXXXXX)"
  ts_normalized="$(mktemp /tmp/exochain-ts-normalized.XXXXXX)"
  jq -s -e --argjson count "$expected_count" \
    'if length == $count and (map(.vector_id) | unique | length == $count)
     then sort_by(.vector_id) else error("missing or duplicate Rust vector output") end' \
    "$rust_output" > "$rust_normalized" || { rm -f "$rust_normalized" "$ts_normalized"; return 1; }
  jq -s -e --argjson count "$expected_count" \
    'if length == $count and (map(.vector_id) | unique | length == $count)
     then sort_by(.vector_id) else error("missing or duplicate TypeScript vector output") end' \
    "$ts_output" > "$ts_normalized" || { rm -f "$rust_normalized" "$ts_normalized"; return 1; }
  local status=0
  diff -u "$rust_normalized" "$ts_normalized" || status=$?
  rm -f "$rust_normalized" "$ts_normalized"
  return "$status"
}

prepare_typescript_executor() {
  local executor_dir="$1"
  test ! -e "$executor_dir"
  mkdir -p "$executor_dir"
  cp "$SCRIPT_DIR/package.json" \
    "$SCRIPT_DIR/package-lock.json" \
    "$SCRIPT_DIR/index.ts" \
    "$SCRIPT_DIR/tsconfig.json" \
    "$executor_dir/"
  (
    cd "$executor_dir"
    npm ci >/dev/null
    npm run typecheck >/dev/null
  )
}

run_typescript_vectors() {
  local executor_dir="$1" vectors="$2" output="$3"
  (
    cd "$executor_dir"
    npx --no-install tsx index.ts --vectors "$vectors" --output "$output"
  )
}

main() {
  local vectors="$SCRIPT_DIR/vectors" verbose=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vectors) vectors="$2"; shift 2 ;;
      --verbose) verbose=true; shift ;;
      *) echo "unknown argument: $1" >&2; return 2 ;;
    esac
  done
  command -v cargo >/dev/null
  command -v node >/dev/null
  command -v npm >/dev/null
  command -v npx >/dev/null
  command -v jq >/dev/null
  test -d "$vectors"
  vectors="$(cd "$vectors" && pwd)"
  local vector_count
  vector_count="$(find "$vectors" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"
  test "$vector_count" -gt 0

  local results rust_output ts_output typescript_executor
  results="$(mktemp -d /tmp/exochain-cross-impl.XXXXXX)"
  trap 'rm -rf "$results"' EXIT
  rust_output="$results/rust.jsonl"
  ts_output="$results/typescript.jsonl"
  typescript_executor="$results/typescript-executor"
  EXOCHAIN_CROSS_IMPL_HASH_VECTORS="$vectors" \
  EXOCHAIN_CROSS_IMPL_OUTPUT="$rust_output" \
    cargo test --manifest-path "$EXOCHAIN_ROOT/Cargo.toml" -p exochain-core \
      --test cross_impl_hash_vectors cross_impl_hash_vectors_match_golden -- --exact --nocapture
  prepare_typescript_executor "$typescript_executor"
  run_typescript_vectors "$typescript_executor" "$vectors" "$ts_output"
  compare_vector_outputs "$rust_output" "$ts_output" "$vector_count"
  if "$verbose"; then
    jq -s -S 'sort_by(.vector_id)' "$rust_output"
  fi
  printf 'Compared %s committed vector(s): Rust and TypeScript actual outputs are identical\n' "$vector_count"
  rm -rf "$results"
  trap - EXIT
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
```

The pinned dependency installation, typecheck, and vector execution all occur
inside the trap-cleaned `typescript_executor` under the temporary result root.
Only reviewed `package.json`, `package-lock.json`, `index.ts`, and
`tsconfig.json` bytes are copied there. No code in this task creates
`tools/cross-impl-test/node_modules`, `tools/cross-impl-test/results`, or
generated vectors. No external repository is treated as a vector executor.

- [ ] **Step 5: Run GREEN, bad-output regression, and residue checks**

```bash
STATUS_BEFORE="$(mktemp /tmp/df-status-before.XXXXXX)"
STATUS_AFTER="$(mktemp /tmp/df-status-after.XXXXXX)"
cleanup_status_snapshots() {
  rm -f "$STATUS_BEFORE" "$STATUS_AFTER"
}
trap cleanup_status_snapshots EXIT
git status --porcelain=v1 --untracked-files=all > "$STATUS_BEFORE"
bash tools/cross-impl-test/compare_unit_test.sh
bash tools/cross-impl-test/compare.sh --verbose
cargo test -p exochain-core --test cross_impl_hash_vectors cross_impl_hash_vectors_match_golden -- --exact --nocapture
test ! -d tools/cross-impl-test/node_modules
test ! -e tools/cross-impl-test/results
git status --porcelain=v1 --untracked-files=all > "$STATUS_AFTER"
diff -u "$STATUS_BEFORE" "$STATUS_AFTER"
cleanup_status_snapshots
trap - EXIT
```

Expected: the unit test proves a forged TypeScript output and a bad vector
cannot pass; the unit test and gate both use the same temporary TypeScript
executor; the gate prints `Rust and TypeScript actual outputs are identical`;
the temporary TypeScript install/typecheck/vector run and Rust focused test
pass; no repository-local `node_modules` or results directory appears; exact
tracked and untracked status is unchanged by both runs.

- [ ] **Step 6: Commit only the core CI/test-tool hardening**

```bash
git add crates/exo-core/tests/cross_impl_hash_vectors.rs \
  tools/cross-impl-test/compare.sh \
  tools/cross-impl-test/compare_unit_test.sh \
  tools/cross-impl-test/index.js \
  tools/cross-impl-test/index.ts \
  tools/cross-impl-test/package.json \
  tools/cross-impl-test/package-lock.json \
  tools/cross-impl-test/tsconfig.json \
  tools/cross-impl-test/vectors/hash_blake3.json
git diff --cached --check
git commit -m "test: compare real cross-implementation vectors"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

This commit is an isolated EXOCHAIN core CI/test-tool concern inside the slice
PR. It contains no governance proposal/schema content and no runtime behavior.

### Task 6: Complete the slice gate, review package, and PR evidence

**Files:** No new production or governance files. Update the tracked
`.superpowers/sdd/progress.md` ledger and exact report path
`.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-implementer.md`;
preserve the recorded base at
`.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha`.

**Interfaces:**

- Consumes: Tasks 1-5 commit range, including the real-output
  cross-implementation gate and every immutable artifact produced earlier in
  the slice.
- Produces: independently verifiable slice evidence and a PR body that does not
  overstate ratification, CI, merge, deployment, runtime, or publication truth.

- [ ] **Step 1: Run the complete applicable local gate set**

```bash
cargo test -p exochain-decision-forum --test df_protocol_001_normative_contract -- --nocapture
cargo test -p exochain-decision-forum
cargo build --workspace --release
cargo test --workspace
cargo test --workspace --release
cargo tarpaulin --workspace --exclude exochain-wasm --exclude exochain-proofs --out xml --output-dir coverage --engine llvm --timeout 900 --fail-under 90
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit --deny unsound --deny unmaintained
bash tools/test_audit_ignore_policy.sh
cargo deny check
bash tools/test_security_critical_dependencies_pinned.sh
bash tools/test_proprietary_license_boundaries.sh
jq empty governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json governance/schemas/peer-reviewed-protocol-package-v1.schema.json
b3sum governance/proposals/D9-COUNCIL-CHARTER-PROPOSAL.md governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md
```

Run the hardened in-repository cross-implementation gate. Task 5 makes the
canonical Rust and pinned TypeScript implementations execute the same committed
vectors and compare their normalized actual outputs; no external `exo`
repository or test-count proxy is involved:

```bash
set -euo pipefail
STATUS_BEFORE="$(mktemp /tmp/df-cross-status-before.XXXXXX)"
STATUS_AFTER="$(mktemp /tmp/df-cross-status-after.XXXXXX)"
git status --porcelain=v1 --untracked-files=all > "$STATUS_BEFORE"
CROSS_IMPL_OUTPUT="$(mktemp /tmp/df-protocol-001-cross-impl.XXXXXX)"
cleanup_cross_impl() {
  rm -f "$CROSS_IMPL_OUTPUT" "$STATUS_BEFORE" "$STATUS_AFTER"
}
trap cleanup_cross_impl EXIT
bash tools/cross-impl-test/compare.sh --verbose 2>&1 | tee "$CROSS_IMPL_OUTPUT"
rg -n "Rust and TypeScript actual outputs are identical" "$CROSS_IMPL_OUTPUT"
! rg -n "skipped|pass_count|EXO_TS_ROOT|--exo-ts-root" "$CROSS_IMPL_OUTPUT"
test ! -d tools/cross-impl-test/node_modules
test ! -e tools/cross-impl-test/results
git status --porcelain=v1 --untracked-files=all > "$STATUS_AFTER"
diff -u "$STATUS_BEFORE" "$STATUS_AFTER"
cleanup_cross_impl
trap - EXIT
```

Expected: every gate exits 0; coverage is at least 90% under the exact CI
exclusions; the D9 predecessor digest remains exact; the cross-implementation
output reports identical actual results and contains no skip/count/external
root path; and exact tracked plus untracked repository status is unchanged.
Record every command/result in the implementer report. The EXIT trap removes
only temporary output/status files and never deletes or cleans a worktree.

- [ ] **Step 2: Run prohibited-scope and claim searches**

```bash
TASK_BASE_FILE=.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha
TASK_BASE="$(tr -d '\n' < "$TASK_BASE_FILE")"
test "$(printf '%s' "$TASK_BASE" | wc -c | tr -d ' ')" -eq 40
git cat-file -e "$TASK_BASE^{commit}"
git merge-base --is-ancestor "$TASK_BASE" HEAD
git diff --name-only "$TASK_BASE"..HEAD
git diff "$TASK_BASE"..HEAD -- crates/decision-forum/src crates/exo-gateway crates/exo-dag-db-postgres web cybermedica livesafe
git diff --check "$TASK_BASE"..HEAD
rg -n "Status:\*\* (RATIFIED|ENACTED)|binding_mode_allowed\"[[:space:]]*:[[:space:]]*true" governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1*
rg -n -i "retrieval quality|compression|similarity|ranking|token savings|cheaper|economic thesis" governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1* governance/schemas/peer-reviewed-protocol-package-v1.schema.json
```

Expected: changed paths are only those classified by this plan; production and
proprietary subtree diff is empty; binding-status search has no match;
research-term matches occur only in explicit exclusion text naming
`DF-ROADMAP-001`.

- [ ] **Step 3: Dispatch the independent specification and technical validators**

Generate the review package with the task base SHA, then dispatch separate
read-only agents:

1. **Specification validator:** checks exact Amendment 1 and schema coverage,
   immutable D9, advisory/binding boundary, roles/floors, acceptance mapping,
   prohibited extras, path classification, and license boundary.
2. **Technical validator:** checks test evidence, digest handling, schema/type
   consistency, determinism, source-guard strength, security/fail-closed
   semantics, cross-implementation actual-output comparison, repository
   residue behavior, and bypass/threat completeness.

Validator outcomes are exactly `APPROVED`,
`APPROVED_WITH_MINOR_FINDINGS`, or `CHANGES_REQUIRED`, with file/line evidence
and severity. No author is the sole validator.

- [ ] **Step 4: Fix all critical/important findings and obtain re-review**

Record both outcomes in the ledger. Any critical or important finding goes to
a fresh fixer/implementer using the same recorded `TASK_BASE`; run the finding's
focused RED/GREEN command and every affected Task 6 gate, commit the coherent
fix without rewriting history, and return the amended range to the original
specification and technical validators. Repeat only until both validators
return `APPROVED` or `APPROVED_WITH_MINOR_FINDINGS`. Preserve every minor
finding in the ledger and implementer report for the whole-slice reviewer.

- [ ] **Step 5: Write the evidence report and commit the recovery ledger**

Only after both independent validators approve, write the exact implementer
report and append validator identities, outcomes, findings, fixes, and gate
results to the ledger. The task-base file and initial ledger entry were already
committed before RED and MUST remain byte-identical; stage only the ledger and
implementer report, then validate the complete tracked range plus untracked
state against the recorded base:

```bash
git add .superpowers/sdd/progress.md \
  .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-implementer.md
TASK_BASE="$(tr -d '\n' < .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha)"
test "$(git show "$(git log --format=%H --follow -- .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha | tail -n 1)":.superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha | tr -d '\n')" = "$TASK_BASE"
git diff --cached --check
diff -u \
  <(printf '%s\n' \
    .superpowers/sdd/progress.md \
    .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-implementer.md \
    .superpowers/sdd/reports/df-protocol-001/01-charter-normative-schema-task-base.sha \
    Cargo.lock \
    crates/decision-forum/Cargo.toml \
    crates/decision-forum/tests/df_protocol_001_normative_contract.rs \
    crates/exo-core/tests/cross_impl_hash_vectors.rs \
    governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.manifest.json \
    governance/proposals/D9-COUNCIL-CHARTER-AMENDMENT-1.md \
    governance/schemas/peer-reviewed-protocol-package-v1.schema.json \
    governance/threat_matrix.md \
    governance/traceability_matrix.md \
    tools/cross-impl-test/compare.sh \
    tools/cross-impl-test/compare_unit_test.sh \
    tools/cross-impl-test/index.js \
    tools/cross-impl-test/index.ts \
    tools/cross-impl-test/package-lock.json \
    tools/cross-impl-test/package.json \
    tools/cross-impl-test/tsconfig.json \
    tools/cross-impl-test/vectors/hash_blake3.json | sort) \
  <({ git diff --name-only "$TASK_BASE"..HEAD; git diff --cached --name-only; } | sort -u)
git status --porcelain=v1 --untracked-files=all
test ! -d tools/cross-impl-test/node_modules
test ! -e tools/cross-impl-test/results
git commit -m "docs(governance): record DF protocol slice evidence"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Expected: the final evidence commit contains only the ledger and implementer
report; the immutable base record remains unchanged in its earlier
evidence-control commit. The full `TASK_BASE..HEAD` plus staged path list is
exactly the classified set, including the deliberate `index.js` deletion, and
contains no runtime/proprietary path. The final exact status assertion is empty;
the recorded base/report paths are preserved, not removed to manufacture
cleanliness.

- [ ] **Step 6: Dispatch the independent whole-slice reviewer**

Dispatch a fresh read-only whole-slice reviewer with the immutable base, full
base-to-head diff, implementer report, both validator reports, all minor
findings, and complete gate evidence. The outcome vocabulary is the same
three-value validator vocabulary. Recovery order is exact: fresh fixer, then
the original specification and technical validators re-review the amended
range, then an append-only evidence-update commit records their results, then
the whole-slice reviewer re-reviews the complete range. Never amend or
force-push the prior evidence commit. Slice completion requires whole-slice
approval and an empty exact worktree-status assertion after the last evidence
update.

- [ ] **Step 7: Prepare the slice PR body**

The PR body must contain these headings and evidence:

```markdown
## Path classification
## Authority and security impact
## RED and GREEN evidence
## Focused and full applicable gates
## Bypass and prohibited-scope search
## License boundary
## DAG DB persistence impact
## Rollback
## Unresolved risks and minor findings
## Truth boundaries
```

State explicitly: documentation/schema/source-guard only; no production
mutation; no database migration; no runtime route; no credential; no
ratification; no binding activation; no deployment; no package publication.
Rollback is the ordinary revert of this slice before ratification; the frozen
D9 file remains untouched. Keep the PR draft until independent review and CI
complete.

## Requirements-to-tests traceability for slice 1

| Slice 1 requirement | RED/GREEN evidence | Downstream enforcement owner |
|---|---|---|
| Frozen D9 preserved | `amendment_is_separate_from_frozen_d9_and_remains_nonbinding`; direct `b3sum` | Slice 1 complete |
| Amendment is separate and nonbinding | Amendment guard plus manifest guard | Slice 3 binding-mode gate |
| Roles, rosters, floors, dissent, Chair, envelope, loops, E-STOP, RESET | Amendment required-string guard and independent specification review | Slices 2-4 |
| Exact package component, commitment, signed-review, roster, evidence-floor, and primitive names | Pinned Draft 2020-12 meta-schema compilation; closed `IndependentEvidenceClass` for manifest/quorum/E-STOP binding fields while `ProviderModelJudgment` remains non-binding inventory only; fully rebound/rehashed `[ProviderModelJudgment, IndependentNonProviderEvidence]` rejection before `VerifiedPackageRoot`; semantic binding validator backed by independently verified non-seat and ten-seat authority registries; controller-signed `SeatAttestationSigningPayloadV1`; all-ten-key fully re-signed trust-anchor substitution rejection; exact version/predecessor rules; continuous predecessor-to-successor DAG DB receipt sequences; resolvable body-specific `PeerReviewV1` signature-envelope cases; positive/adversarial `normative_schema_fixes_package_components_and_deterministic_primitives` and `commitment_construction_is_acyclic_and_mutation_complete`; `jq` | Slices 2-6 |
| Content-addressed proposal linkage | `amendment_manifest_binds_exact_bytes_without_enactment`; `b3sum` | Slice 10 ratification/genesis verification |
| Threats T-18 through T-25 | `threat_and_traceability_matrices_cover_df_protocol_001` | Slices 2-8 |
| Acceptance criteria DF-001 through DF-020 | Same matrix guard | Every owning slice; slice 10 closes |
| Core/commercial license separation | `tools/test_proprietary_license_boundaries.sh` | Slices 6-8 and 10 |
| No retrieval/economic-thesis coupling | prohibited-scope search and DF-020 traceability | Slices 4 and 9 |
| Real Rust/TypeScript cross-implementation comparison | `compare_unit_test.sh` mismatch/bad-vector RED/GREEN; per-vector JSONL `diff`; tracked/untracked residue check | Every later slice gate |

## Self-review checklist

- Every design acceptance criterion has an owning slice and stable ID.
- D9 predecessor path and digest match the repository.
- No step edits the frozen D9 or SEAT-000 record.
- No step marks Amendment 1 ratified/enacted or enables binding mode.
- Council, AI-IRB, Chair, Co-PI, and independent-member semantics remain
  separate; Chair approval cannot cure AI dissent or absence.
- The schema field names match the interfaces table and contain no floating
  type, unordered Rust collection, wall-clock field, or random-ID instruction.
- Git SHA-1 object IDs are not conflated with BLAKE3 `Hash256`; HLC zero and
  canonical lowercase UUIDs are represented exactly.
- Council/AI-IRB vote types, signature targets, roster maps, provider/evidence
  enums, dissent/Chair conditionals, and typed resource ceilings reject the
  adversarial instances enumerated by Task 2.
- `ProviderModelJudgment` exists only in the broad non-binding
  `EvidenceClass`; the closed `IndependentEvidenceClass` used by manifest,
  quorum-proof, and E-STOP floor fields excludes it. The exact fully
  rebound/rehashed `[ProviderModelJudgment, IndependentNonProviderEvidence]`
  attack fails transport and semantic validation and cannot yield
  `VerifiedPackageRoot`.
- Every peer review carries a typed `PeerReviewV1` Ed25519 envelope; its
  canonical body-specific payload includes the common authorization target,
  its payload hash is checked, and its signing key resolves through the
  assignment only to `VerifiedSeatAuthorityRegistryV1`, never to an
  in-package attestation. Every `SeatAttestation` is itself controller-signed
  over exact `SeatAttestationSigningPayloadV1` and matched completely to that
  independently produced registry. Bare review or seat-attestation signature
  hashes cannot satisfy the schema.
- The authorization target excludes signing dispositions; the prepublication
  root, in-package publication authorization, normalized final package root,
  and external projection manifest form an acyclic chain. The package embeds
  only predecessor lifecycle/receipt commitments; independently signed current
  action/event/continuing-review receipts reference the already-fixed package
  root in `ProtocolExecutionReceiptChainV1`, and a successor package commits
  that prior chain. Every authoritative field has a mutation or verification-
  failure assertion.
- The verifier recomputes the normalized final package root from package
  content and returns an opaque `VerifiedPackageRoot`; execution-chain and
  action authorization interfaces accept only that verified type, so a
  schema-valid forged stored root cannot authorize execution.
- Version 1 requires both predecessor references to be null; every version 2
  or later requires both to be non-null and to match the separately verified
  predecessor exactly. Half-null and mismatched predecessor cases fail.
- A protocol subject's DAG DB receipt history is continuous: genesis begins at
  sequence 1, a successor begins at predecessor terminal sequence plus 1, its
  first receipt links to the predecessor terminal receipt hash, and explicit
  first/terminal/count metadata rejects resets, gaps, duplicates, and false
  terminal claims.
- Chair, publication, and execution signer authority facts resolve from
  `VerifiedAuthorityRegistryV1`, produced by prior kernel/authority
  verification; package and execution records carry typed references to those
  facts, and attacker-controlled re-signing plus rehashing cannot substitute a
  signer, key, scope, or authority chain.
- Provider/controller/key/context/validity/authority facts resolve from the
  independently produced ten-seat registry with provider-specific, unique
  controller DIDs and independent-control proofs. One-seat substitution,
  controller-signature mutation, authority-chain mismatch, expired/not-yet-
  valid seats, provider-to-provider, shared-controller,
  provider-controls-independent, and Chair/Co-PI-controls-independent cases
  fail. A fully re-signed package that replaces every seat key and dependent
  commitment also fails while the trusted registry remains unchanged.
- Every JSON integer promised as `u64`, including HLC `physical_ms`, protocol
  version, scheduled HLC units, and every resource ceiling, is capped at
  `18446744073709551615`.
- Cross-implementation evidence compares actual per-vector outputs from the
  canonical Rust and TypeScript executors and fails on skips, bad vectors,
  missing output, duplicates, divergence, or repository residue.
- Database/runtime/product work is absent from this slice.
- New threat and traceability rows remain non-green until their assigned
  implementation evidence exists.
- Core and proprietary paths are not mixed.
- Every task has an observable RED, minimal GREEN, focused gate, explicit
  staging set, coherent commit, implementer report, and independent review.
