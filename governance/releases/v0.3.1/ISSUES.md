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

# v0.3.1 draft implementation issues

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

These are markdown drafts for humans to review. They are not GitHub issues.
Do not file them. Do not start the market drafts while milestone 1 is
unrecorded or while any GD-031 record is PENDING.

## Proposed milestones

[V030-CLOSE-ASSESSMENT.md](V030-CLOSE-ASSESSMENT.md) recommends path B: roll
the v0.3.0 close into this release as gating milestone 1, and do not cut a
separate 0.3.0 tag. That recommendation is not adopted. GD-031-01 stays
PENDING. The two drafts below are the proposed milestone-1 scope. The 28
market drafts stay where they are and stay blocked.

| Milestone | Drafts | What "done" means |
| --- | --- | --- |
| 0 | This package | Documents exist. Nothing is implemented. Nothing is approved |
| 1 | V030-M1-01, V030-M1-02 | The eight v0.3.0 rows hold, including the two that are still partial. #813 stays out unless humans narrow it |
| 2 and after | V031-D01 through V031-G02 | Milestone 1 is recorded and the matching GD-031 record is signed |

### V030-M1-01 — Payment evidence is a non-zero BLAKE3 of canonical CBOR

- **Scope.** `exo-pdp` only. `parse_bound_hash` already rejects 32 zero
  bytes on `verify` and has no test. `handle_decide` accepts those bytes as
  `Some(Hash256::ZERO)`. Add the same rejection there. Add a function that
  BLAKE3-hashes canonical CBOR of the payment-evidence body, including
  `PAYMENT_EVIDENCE_DOMAIN` (`exo.x402.payment.evidence.v1`), via
  `exo_core::hash::hash_structured`. A caller hex is evidence only when it
  equals that digest. Header-only `PAYMENT-SIGNATURE` stays HTTP 402.
- **Acceptance.** Zero hash fails closed on both ingresses. A non-zero hash
  that is not the canonical digest fails closed. An unpaid permitted
  commercial mandate stays `Decision::Challenge` and HTTP 402. Deny with a
  matching digest stays HTTP 403.
- **Tests.** New tests beside `header_presence_is_not_payment` and
  `deny_outranks_valid_payment`. Existing tests
  `missing_payment_is_challenge_when_otherwise_permitted` and
  `valid_payment_still_denied` stay green.
- **Dependencies.** None. This is milestone 1. No new crate.
- **Risk.** High.

### V030-M1-02 — The release record does not claim spec §19.6.1

- **Scope.** One sentence in the future release record: this release does
  not claim specification §19.6.1, and #810 stays open. No `cgr_trace`
  producer. #813 stays outside milestone 1 unless humans narrow that issue
  to the eight GOAL rows.
- **Acceptance.** The sentence is in the release record. The tree gains no
  producer for `cgr_trace/`.
- **Tests.** A source guard can search the release record for the non-claim
  sentence. There is no new runtime test, because the row adds no runtime.
- **Dependencies.** None. Humans write the record. This draft does not file
  #810 and does not close it.
- **Risk.** Medium.

Risk tiers: **Critical** (authority, payment truth, coverage truth, or
publication), **High** (protocol correctness), **Medium** (interoperability
or bounds), **Low** (client convenience on top of a specified HTTP API).

Every issue inherits the workspace bans: no `HashMap`/`HashSet`, no floating
point, no `SystemTime`/`Instant` in protocol logic, no `unsafe`, no
`unwrap`/`expect` outside tests. Hashed bodies are canonical CBOR.

Count: 28 market drafts, plus milestone-1 drafts V030-M1-01 and V030-M1-02.
Market drafts: discovery 4, negotiation 5, authority 4, execution 3,
settlement 3, verification 5, assurance interfaces 2, AI-SDLC governance 2.

Common dependency: milestone 1 recorded (see the drafts above; the label
`V030-CLOSE` means that record) plus the GD-031 record that authorizes
implementation. Individual dependencies are additional. Under the proposed
path B, commercial settlement and assurance drafts stay schemas until
GD-031-02, GD-031-03, and GD-031-10 are signed. CEO direction on 2026-10-09
says those commercial lines are preparatory and that there is no assurance
partner yet, so `coverage_claim` stays `none`. That direction is not a
signature.

## Discovery

### V031-D01 — Point the existing discovery document at commercial HTTP routes

- **Scope.** Extend `ExochainDiscoveryResponse` with optional commercial
  route names. Do not remove or rename current fields.
- **Acceptance.** `GET /.well-known/exochain.json` still serves health, ready,
  AVC routes, SDK names, and MCP metadata. New fields are absent when the
  unaudited feature is off. When on, they name the bailment and x402 paths
  and set no permission.
- **Tests.** Golden JSON for the feature-off document equals today's
  canonical document. Feature-on document validates against
  `schemas/discovery-profile.schema.json`.
- **Dependencies.** None beyond the common gate. Feature-matrix entry
  required before the feature exists.
- **Risk.** Medium.

### V031-D02 — Serve a signed A2A Agent Card

- **Scope.** `GET /.well-known/agent-card.json` per
  `specs/MCP-A2A-DISCOVERY.md`. No A2A task RPC.
- **Acceptance.** Card signature verifies under the pinned service key.
  `grants_authority` is false. Missing feature or missing key returns a
  fail-closed error, not an unsigned card.
- **Tests.** Vector `test-vectors/discovery-card.json`. Tampered byte fails
  verification. A card with `grants_authority: true` is rejected by the
  client helper.
- **Dependencies.** V031-D01.
- **Risk.** High.

### V031-D03 — SDK and HTTP clients for discovery

- **Scope.** `packages/exochain-sdk` and `packages/exochain-py` functions that
  GET the two documents and verify the card. HTTP remains sufficient without
  the SDK.
- **Acceptance.** A client built from the schema alone, and these SDKs, both
  accept the same vector and reject the same tamper. Timeouts and non-200
  responses surface as errors. The SDK does not synthesize Allow.
- **Tests.** Cross-language vector replay. No workspace crate linked into the
  "third party" fixture process.
- **Dependencies.** V031-D02.
- **Risk.** Low.

### V031-D04 — Discovery poisoning controls

- **Scope.** Client pin of service DID. Reject unsigned cards, mismatched
  keys, and tool results that contain a permission grant.
- **Acceptance.** Lookalike host in `supported_interfaces` is not contacted
  when the signature fails. MCP tool output cannot change the local
  permission set.
- **Tests.** Vector with a wrong key. Unit test that a tool payload
  containing `permissions` leaves the authority context unchanged.
- **Dependencies.** V031-D02, V031-A01.
- **Risk.** High.

## Negotiation

### V031-N01 — Bilateral transcript on top of exo-consent

- **Scope.** Hash-linked proposal and commit messages. Commit calls
  `exo-consent` activation only after PDP Allow. No new bailment struct.
- **Acceptance.** Status moves `Proposed` to `Committed` only with both
  signatures and Allow. `propose` remains the constructor for the underlying
  record.
- **Tests.** Deterministic CBOR hash of the same messages twice. Replay of
  `prev_hash` fails.
- **Dependencies.** V031-A01, V031-A03.
- **Risk.** High.

### V031-N02 — Counteroffer subset rule

- **Scope.** Counteroffer replaces `terms_hash`. Permission list must be a
  subset of the proposal ceiling. Price is an integer and may change.
- **Acceptance.** Adding a permission does not append. Dropping a permission
  does. Amount uses integer minor units.
- **Tests.** Superset fixture denied. Subset fixture hashes stably.
- **Dependencies.** V031-N01, V031-A02.
- **Risk.** High.

### V031-N03 — Multipartite party set

- **Scope.** Three or more parties in a `BTreeMap` by DID. Integer threshold.
  Required bailor and bailee signatures.
- **Acceptance.** Missing a required role does not activate. Party order in
  the JSON does not change the CBOR hash.
- **Tests.** Vector `test-vectors/bailment-multipartite.json`. Shuffled JSON
  party order, identical hash.
- **Dependencies.** V031-N02.
- **Risk.** High.

### V031-N04 — Fulfillment and discharge

- **Scope.** Fulfillment message stores the execution hash. Discharge is a
  threshold signature over that hash. Discharge does not mint a new payment.
- **Acceptance.** Discharge before fulfillment is rejected. Discharge does
  not edit kernel configuration.
- **Tests.** State-machine cases for the legal edges in the negotiation spec.
- **Dependencies.** V031-N03, V031-E02.
- **Risk.** High.

### V031-N05 — Dispute bounds

- **Scope.** One open dispute, integer cap per party, closed reason codes,
  no permission change, no deadline reset.
- **Acceptance.** The second open dispute is rejected. An upheld remedy hash
  is still a subset of the ceiling. `human_override_preserved` stays true.
- **Tests.** Cap fixture. Remedy-widening fixture denied.
- **Dependencies.** V031-N03, V031-E03.
- **Risk.** High.

## Authority

### V031-A01 — Compute NoSelfGrant at market ingress

- **Scope.** Set `is_self_grant` from the request bytes. Do not trust a
  caller-supplied false. Wire the flag into `check_no_self_grant` before
  any 402 mapping.
- **Acceptance.** Actor equal to grantor, or a non-subset permission set,
  yields the invariant violation and HTTP 403. The successful demonstration
  path has the flag false because the human principal is the grantor and the
  agent stays inside the ceiling.
- **Tests.** Negative fixture `test-vectors/self-grant-denied.json`. The
  agent DID is not an approver in any code path this issue adds.
- **Dependencies.** `V030-CLOSE`.
- **Risk.** Critical.

### V031-A02 — Commercial mandates narrow only

- **Scope.** Market links go through `AuthorityChain` verification.
- **Acceptance.** A wider child link is `AuthorityError`. `delegation_allowed
  = false` blocks child AVC minting inside negotiation.
- **Tests.** Existing widening tests plus a market counteroffer that tries
  to widen.
- **Dependencies.** V031-A04.
- **Risk.** Critical.

### V031-A03 — Consent, revocation, and one policy decision

- **Scope.** `ConsentRequired` before execution. Revocation checked in
  consent, AVC, authority, and PDP sets. Only
  `verify_before_settle` emits the decision.
- **Acceptance.** Proposed bailments do not authorize execution. Any
  revocation denies. A second decision function is absent.
- **Tests.** Each revocation source independently. Source guard that market
  routes call `verify_before_settle`.
- **Dependencies.** V031-A04.
- **Risk.** Critical.

### V031-A04 — Principal and agent DID binding

- **Scope.** Ed25519 signatures over canonical bytes. 0dentity device and
  behavior features remain off and are not inputs.
- **Acceptance.** Unknown keys fail closed. A credential for a different
  agent DID fails. No 0dentity sample is required.
- **Tests.** Wrong-key fixture. Build with default features does not enable
  unaudited 0dentity axes.
- **Dependencies.** `V030-CLOSE`.
- **Risk.** High.

## Execution

### V031-E01 — Execute only after Allow and an active bailment

- **Scope.** Execution entry checks PDP evidence decision Allow and bailment
  status Active.
- **Acceptance.** Deny, Challenge, Proposed, and Expired do not run the
  service. The service function is not called on those paths.
- **Tests.** Table of decision by status.
- **Dependencies.** V031-A01, V031-N04's message type, V031-S02.
- **Risk.** Critical.

### V031-E02 — Fulfillment hash

- **Scope.** Emit a BLAKE3 fulfillment hash bound to the transcript id and
  the Allow evidence hash. No new permissions in the payload.
- **Acceptance.** Same inputs, same hash. Tamper changes the hash. Payload
  has no permission field that the authority layer reads as a grant.
- **Tests.** Determinism. Extra-field rejection.
- **Dependencies.** V031-E01.
- **Risk.** Medium.

### V031-E03 — Human override stays on

- **Scope.** Market contexts set `human_override_preserved`. No message
  clears it.
- **Acceptance.** A fixture that sets the flag false is rejected by
  `HumanOverride` before execution.
- **Tests.** Invariant test using the market context builder.
- **Dependencies.** V031-A01.
- **Risk.** Critical.

## Settlement

### V031-S01 — Market calls the existing x402 adapter

- **Scope.** Commercial mandate uses `X402VerifyRequest` and
  `map_decision_to_http`. No new status table.
- **Acceptance.** Unpaid permitted mandate is 402. Denied mandate is 403
  with or without a hash. `never_moves_money` stays true.
- **Tests.** Vector `test-vectors/x402-challenge.json` and a deny-with-hash
  case. Regression that #815/#816 shapes are not imported.
- **Dependencies.** `V030-CLOSE`.
- **Risk.** Critical.

### V031-S02 — Bind payment evidence to the mandate and the terms

- **Scope.** Preimage includes mandate hash, terms hash, amount, currency,
  under `exo.x402.payment.evidence.v1`. Store the hash on the AVC receipt
  field that already exists.
- **Acceptance.** A hash from another mandate is not paid. Legacy receipt
  signing payload still verifies when the field is absent.
- **Tests.** Replay fixture. Existing
  `payment_evidence_hash_is_recorded_without_breaking_legacy_payloads`
  remains green.
- **Dependencies.** V031-S01.
- **Risk.** Critical.

### V031-S03 — Never-paywall list and no take-rate

- **Scope.** Validate, 0dentity, and agent consent paths stay free. No
  platform fee field.
- **Acceptance.** `is_never_paywalled_path` still true for those paths.
  Economy quote on the demonstration policy charges zero. A take-rate field
  in a market request is an unknown field and is rejected.
- **Tests.** Path table. Schema rejection. GD-031-02 still PENDING means the
  feature cannot enable a fee.
- **Dependencies.** V031-S01.
- **Risk.** High.

## Verification

### V031-V01 — Stamp market claims on the existing hop

- **Scope.** Stamp `crosschecked.claim.v1` over the bundle hash via
  `POST /api/v1/avc/claims/stamp`. Do not mint a trust receipt there.
- **Acceptance.** Response `proof_kind` is `Rfc3161`. A new kind is not
  required. Validate's response shape is unchanged.
- **Tests.** Vector `test-vectors/claim-stamp-request.json` shape. Assert
  the route remains free of payment logic.
- **Dependencies.** `V030-CLOSE`.
- **Risk.** High.

### V031-V02 — Public Microsoft token verification

- **Scope.** Copy token, imprint, policy OID, nonce, serial, authority DID,
  URL, and SPKI pin into the bundle. Second verifier uses only those bytes.
- **Acceptance.** AC-6 and AC-9. No Azure credential in the verifier input
  set. Pin mismatch fails.
- **Tests.** `test-vectors/second-verifier-public-inputs.json` lists the
  allowed input names and forbids privileged ones.
- **Dependencies.** V031-V01.
- **Risk.** Critical.

### V031-V03 — Labelled RFC 3161 fallback

- **Scope.** A non-Microsoft TSA is accepted only when the bundle names its
  URL, DID, policy OID, and pin. It is not relabelled as
  `did:exo:microsoft-public-rsa-tsa`.
- **Acceptance.** The current stamp hard-check is either preserved for the
  Microsoft demonstration profile or explicitly branched with the label
  rule. Silent fallback fails tests.
- **Tests.** Fallback token presented under the Microsoft DID is rejected.
- **Dependencies.** V031-V02. GD-031-11 for any production dependency on the
  Microsoft URL.
- **Risk.** High.

### V031-V04 — Canonical bundle manifest

- **Scope.** `exo.market.evidence_bundle.v1` referencing existing pack,
  legal bundle, receipt, and stamp hashes. Not returned by AVC validate.
- **Acceptance.** Six sections plus timestamp. Zero hash is not success.
  Tamper changes the BLAKE3 manifest hash. No secret fields.
- **Tests.** Vector `test-vectors/evidence-bundle-manifest.json`. Route test
  that validate's body does not contain `exo.market.evidence_bundle.v1`.
- **Dependencies.** V031-E02, V031-S02, V031-V02.
- **Risk.** High.

### V031-V05 — Two independent implementations over the vectors

- **Scope.** One implementation is the workspace. The second reads only
  `schemas/` and `test-vectors/` plus public crypto libraries.
- **Acceptance.** AC-8. Identical decisions on every vector. The second tree
  does not depend on `exo-*` crates.
- **Tests.** The demonstration procedure in `DEMO.md`.
- **Dependencies.** V031-D03, V031-V04.
- **Risk.** High.

## Assurance interfaces

### V031-F01 — Assurance interface schema and fail-closed adapter

- **Scope.** Implement the interface object and the `submit` shape in
  `specs/FINANCIAL-ASSURANCE.md`. Default configuration has an empty issuer.
- **Acceptance.** `coverage_claim` other than `none` is invalid.
  `exochain_is_obligor: true` is invalid. Missing partner configuration
  rejects submit. A rejected submit does not change the PDP decision.
- **Tests.** Vector `test-vectors/assurance-interface.json`. Partner
  response that names EXOCHAIN as issuer is rejected.
- **Dependencies.** V031-V04. GD-031-10 before any non-empty issuer.
- **Risk.** High.

### V031-F02 — Non-coverage language guard

- **Scope.** A source and docs scan, once market crates exist, for the
  forbidden phrases in the assurance spec. `AssuranceClass` names stay
  classifiers.
- **Acceptance.** The phrases fail the guard. The fixed statement sentence
  is allowed only as the schema's required value.
- **Tests.** Guard fails on a planted string "insured by EXOCHAIN" and
  passes on this proposal's spec, which states the prohibition and the
  fixed sentence.
- **Dependencies.** V031-F01.
- **Risk.** Critical.

## AI-SDLC governance

### V031-G01 — Risk-tier human approval, mechanically

- **Scope.** Encode the tiers from GD-031-09 only after that record is
  filled. Until then, no agent-written change to authority, consent,
  settlement, or release metadata merges.
- **Acceptance.** Agent identities are absent from approver sets. A change
  classified Critical requires two distinct human approvals and cannot be
  approved by the committing agent. Self-review is disabled.
- **Tests.** Fixture where the agent DID equals an approver DID is rejected.
  This is `NoSelfGrant` applied to the engineering action, not a policy
  paragraph.
- **Dependencies.** V031-A01. GD-031-09 must be filled before the tiers are
  code. Drafting this issue did not fill it.
- **Risk.** Critical.

### V031-G02 — Independent verification of agent-produced changes

- **Scope.** A verifier distinct from the authoring agent reruns the issue's
  named tests and the publication and claim guards.
- **Acceptance.** The authoring agent's report is not the verification
  record. The record names the command and the exit code.
- **Tests.** A verification record without a command hash is incomplete and
  cannot satisfy a Critical issue.
- **Dependencies.** V031-G01.
- **Risk.** High.
