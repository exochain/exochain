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

# v0.3.0 close assessment

**Status: PROPOSAL. Engineer assessment and recommendation. Not a release record. Not approved. This document does not claim release readiness, and it does not close v0.3.0.**

Assessed tree: `main` at `a2667295e49bdf357f5ed53ff5ddef15ace5f727` ("fix(release): accept upload 201s and resume the partial 0.2.7 draft (#852)"). That commit is an ancestor of this branch. Git tag `v0.2.7` exists. No `v0.3.0` tag exists. The in-repo publication snapshot is unchanged and still records v0.2.4.

The checklist is the eight "Must be true before any tag" rows in [governance/releases/v0.3.0/GOAL.md](../v0.3.0/GOAL.md). Scores come from the source and tests on that commit, plus GitHub issue and pull-request state read on 2026-10-10. This file records a reading of those tests. It does not record a fresh `cargo test` run.

CEO direction recorded alongside this assessment, and left unsigned, is in [GOVERNANCE-DECISIONS.md](GOVERNANCE-DECISIONS.md). Bob Stewart wrote on 2026-10-09 at 11:33 PM ET: "We have to finish 0.3.0 or roll it up and in… the commercial lines is preparatory as we have no assurance partner yet." That sentence offers two release shapes. This file recommends one. It does not choose for him, and it does not fill a signature line.

## Item scores

| # | Must be true | Score | Evidence |
| --- | --- | --- | --- |
| 1 | Unpaid commercial Allow returns 402 Challenge | DONE | `crates/exo-pdp/src/policy.rs` `missing_payment_is_challenge_when_otherwise_permitted` expects `Decision::Challenge` and reason `payment evidence missing`. `crates/exo-pdp/src/x402.rs` `header_presence_is_not_payment` expects `Decision::Challenge` and HTTP 402. `commercially_gated` plus a missing bound hash returns Challenge before Allow. `map_decision_to_http` maps Challenge to 402. Commit `1fb7b087de1cc0857d2059b07bb21f2afccd0370`, merged by `e0e6dacf87e565f3729e2fa6acb95baf26d16e64` (#818). Both are ancestors of `a2667295`. |
| 2 | Deny outranks a bound hash | DONE | `policy.rs` `deny_outranks_valid_payment` expects `Decision::Deny` and `payment_outranked`. `x402.rs` `valid_payment_still_denied` expects HTTP 403 with a non-zero hash attached. `deny_never_maps_to_402` maps Deny to 403 even when `payment_bound` is true. Same commits as row 1. |
| 3 | Payment evidence is a non-zero BLAKE3 hash of canonical CBOR. Zero hash and header-only proofs fail closed | PARTIAL | Header-only is tested: `header_presence_is_not_payment` keeps `PAYMENT-SIGNATURE` unpaid and returns 402. `parse_bound_hash` in `x402.rs` rejects a 32-byte zero hash with `payment evidence hash must be non-zero`. No test calls that branch. `policy.rs` `bound_payment_hash` treats `Hash256::ZERO` as unbound, so a zero hash cannot become Allow. `http.rs` `handle_decide` accepts 32 zero bytes as `Some(Hash256::ZERO)` and does not return that bad-request; policy then Challenges. `PAYMENT_EVIDENCE_DOMAIN` (`exo.x402.payment.evidence.v1`) is a constant asserted in `never_paywalled_paths_include_validate_identity_and_consent`. No function in `exo-pdp` hashes canonical CBOR under that domain. Any other non-zero 32-byte hex is accepted. Same commits as row 1 for the code that does exist. |
| 4 | AVC receipts record `payment_evidence_hash` without breaking legacy signatures | DONE | `crates/exo-avc/src/receipt.rs` field `payment_evidence_hash`. `signing_payload` uses `PaymentBoundExtendedReceiptSigningPayload` only when the hash is `Some`; otherwise the extended payload omits the field. Test `payment_evidence_hash_is_recorded_without_breaking_legacy_payloads` records the hash, verifies both receipt ids, and shows the payloads differ. Same commits as row 1. |
| 5 | #812 `exochain-core` builds from crates.io (`ml-dsa` without default `pkcs8`) | DONE | Workspace `Cargo.toml` pins `ml-dsa` to `=0.1.0-rc.7` with `default-features = false` and `features = ["zeroize"]`, comment citing #812. Published crate `exochain-core` 0.2.7 (unyanked, created 2026-09-18) has the same table: version `=0.1.0-rc.7`, `features = ["zeroize"]`, `default-features = false`. 0.2.4 is also unyanked. Issue #812 is CLOSED COMPLETED (2026-08-17T19:46:14Z). Bob's comment on 2026-08-17 names the #818 pin. Commit `e0e6dacf`. `tools/test_security_critical_dependencies_pinned.sh` `require_exact_pin "ml-dsa" "0.1.0-rc.7"` checks the version. It does not assert `default-features = false`. This assessment read the published manifest. It did not recompile a downstream consumer. |
| 6 | #815 and #816 are superseded and closed | DONE | Pull request #815 CLOSED 2026-08-17T17:29:37Z, `mergedAt` null. Bob Stewart: superseded by #818; do not merge, because it would put the facilitator inside `validate_avc`. Pull request #816 CLOSED 2026-08-17T17:29:39Z, draft, `mergedAt` null. Bob Stewart: superseded by #818; header-presence-is-not-paid is a PDP test; SKU, AACP, and CIM stay out. Superseding merge is #818, commit `e0e6dacf`. No further code. |
| 7 | #810 CGR traces stay out unless the tag claims spec §19.6.1 | PARTIAL | Issue #810 is OPEN: "CGR reduction traces are never produced: spec §19.6.1 `cgr_trace/` has no producer and no bundle field can carry one." The goal forbids claiming §19.6.1. There is no v0.3.0 tag and no release record on this commit that states the non-claim. Combinator and holon trace code already shipped with the 0.2.4 cut and is on `a2667295`. Satisfying this row is a written non-claim in the release record. Implementing a `cgr_trace` producer would be the opposite of the row. |
| 8 | #789 two-person release approval is enforced | DONE | Issue #789 CLOSED COMPLETED 2026-09-08T14:15:34Z. `.github/workflows/release.yml` jobs `approve` (`environment: release`) and `approve-second` (`environment: release-second`) are required by later publish jobs. The second job entered in `2a85a55a` ("chore(release): prepare 0.2.4 authorization release candidate"). Observed 2026-10-10 via the environments API: `release` required reviewer `mstewartbz`, `prevent_self_review` true; `release-second` required reviewers `tazmon95` and `robst3w` (one of), `prevent_self_review` true. The control is in force for a future tag. No v0.3.0 tag has passed it. |

Rows 1, 2, 4, 5, 6, and 8 are already true on the published line that includes 0.2.4 and 0.2.7. Rows 3 and 7 are the remaining goal gaps. Row 3 is code and tests in `exo-pdp`. Row 7 is a sentence in a release record.

## GitHub state checked on 2026-10-10

| Issue or PR | State | What that means for this goal |
| --- | --- | --- |
| #789 | CLOSED, completed, 2026-09-08 | Two-person publication stop. The workflow and environments still enforce it. |
| #810 | OPEN | Spec §19.6.1 stays unclaimed. Leave the issue open. |
| #812 | CLOSED, completed, 2026-08-17 | crates.io pin landed with #818 and is in the 0.2.7 crate. |
| #813 | OPEN | Evidence-grade release integration. Body says `RELEASE_STOPPED_FAIL_CLOSED`. Frozen candidate `bob-stewart/v0.3.0-release-integration` at `92c0d931`. |
| #815 | CLOSED, not merged, 2026-08-17 | Superseded by #818. |
| #816 | CLOSED, not merged, draft, 2026-08-17 | Superseded by #818. |

#813 is a larger train than the eight rows. `main` at `a2667295` contains only `governance/releases/v0.3.0/GOAL.md` under that release directory. The frozen candidate's index documents are absent here. A milestone that closes the eight rows leaves #813 open unless humans narrow that issue. This recommendation does not adopt the frozen candidate and does not mark G00 passed.

## What a separate 0.3.0 tag would cost

Publication is the painful part. The 0.2.7 line shows it.

`release.yml` will not publish until both `approve` and `approve-second` succeed. Environment `release` requires `mstewartbz` and refuses self-review. Environment `release-second` requires one of `tazmon95` (Taz) or `robst3w` (Robert) and refuses self-review. Later publish jobs are themselves bound to `release`, so Max's review sits on the approval job and again on the jobs that upload. That matches the cycle just run: Max, and then Robert or Taz, on a workflow that has already proved fragile.

This history contains ten `v0.2.7-recover.*` tags. `a2667295` (#852) exists because a partial draft had to be resumed and an upload HTTP 201 had to be accepted. The behaviors in rows 1, 2, and 4 have been on `main` since #818 (2026-08-17) and rode out inside the 0.2.4 and 0.2.7 publications. A new 0.3.0 tag would buy a name for that foundation and would spend another full run of the same gates.

## Recommendation: path B

Roll the v0.3.0 goal into the v0.3.1 release. Treat the eight rows as gating milestone 1. Do not cut a separate 0.3.0 tag first.

Path A (finish and tag 0.3.0 on its own) is the same engineering as milestone 1, followed by a signed tag and a full publication: both environments, the upload path that #852 had to repair, and a second publication later for any market release. The code that is already DONE would be re-released to attach a version number.

Path B spends that publication once, when a later authorized release is actually published. Milestone 1 is the gate that market drafts cannot cross. It is a review record plus the small `exo-pdp` gap. It is not a GitHub release and it is not an authorization to start C1–C8.

This is an engineer recommendation. GD-031-01 stays PENDING. Bob's sentence leaves the choice open.

### Remaining work under path B

Milestone 1, still inside this proposal until a human adopts it:

1. In `crates/exo-pdp`, reject a 32-byte zero payment-evidence hash on both `verify` and `handle_decide`, with tests. `parse_bound_hash` already rejects it; `handle_decide` does not, and nothing tests the reject.
2. In `crates/exo-pdp`, hash payment evidence as BLAKE3 over canonical CBOR that includes `PAYMENT_EVIDENCE_DOMAIN`, using `exo_core::hash::hash_structured` / `ciborium`. Accept a caller hash when it equals that digest. Today the domain string is unused and any non-zero 32-byte hex is treated as evidence.
3. When a release record is written, state that the release does not claim specification §19.6.1 and that #810 stays open. Add no `cgr_trace` producer.
4. State in that same record that #813 stays outside milestone 1 unless humans narrow #813 to the eight rows.

Optional hardening, not required to score row 5 as DONE: extend `tools/test_security_critical_dependencies_pinned.sh` so the `ml-dsa` entry must keep `default-features = false`.

No new crate. No workflow edit. No tag. Market issues in [ISSUES.md](ISSUES.md) stay blocked on milestone 1 and on the PENDING GD-031 records.

The publication that still remains is the one at the end of the rolled release. It still requires `mstewartbz` on `release` and Taz or Robert on `release-second`. Path B removes the extra tag. It does not remove those humans from the eventual publication.

### Why path A is the heavier one

Path A is cleaner only when the organization wants a named trust-foundation tag before any market document can say "v0.3.0 closed." The behavior that tag would certify is already on the 0.2.7 line, except the two partial rows. Paying a full publication to name it repeats the 0.2.7 cost (two environments, a fragile draft/upload path, ten recovery tags on that cycle) before any market work starts, and the market release pays it again.

## Draft restructure if path B is adopted

The text below is a draft for [GOAL.md](GOAL.md) and [ISSUES.md](ISSUES.md). It is applied in those files as a proposed shape. Adopting it is a human decision on GD-031-01. Until that signature exists, the draft changes no runtime and authorizes no issue to be filed.

### GOAL.md

Keep the mission, the eight capabilities, and the non-goals. Replace the single gate "no implementation until a v0.3.0 tag exists" with three milestones:

- Milestone 0 is this document package. It is docs, schemas, and fixtures. It is the current pull request. It closes nothing.
- Milestone 1 is the v0.3.0 close. Scope is rows 3 and 7 above, plus an explicit statement that rows 1, 2, 4, 5, 6, and 8 already hold on `a2667295`, plus the statement that #813 and §19.6.1 stay out. Milestone 1 is gating: no market issue starts until a human records that the eight rows hold.
- Milestone 2 and after are C1–C8, in the dependency order already in [DEPENDENCY-GRAPH.md](DEPENDENCY-GRAPH.md). They also wait on the GD-031 signatures.

Commercial settlement and assurance stay inside milestone 2 as interfaces and schemas. `coverage_claim` stays `none`. That follows the CEO direction of 2026-10-09 and still requires GD-031-02, GD-031-03, and GD-031-10 to be signed before any of those schemas gain a runtime that charges a fee or names an issuer.

### ISSUES.md

Add two milestone-1 drafts, `V030-M1-01` (zero-hash fail-closed and canonical-CBOR payment digest, `exo-pdp` only) and `V030-M1-02` (release-record non-claim of §19.6.1, no producer). Leave the 28 market drafts in place. Point their common dependency at milestone 1 and at the GD-031 records, in place of a separate v0.3.0 tag. Do not file any of them on GitHub from this package.
