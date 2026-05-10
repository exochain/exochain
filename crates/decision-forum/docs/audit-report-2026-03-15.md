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

# decision.forum Audit Report — 2026-03-15

## Scope
- `src/*.rs`
- `docs/bayesian-policy-spec.md`

## Findings Closed
- Replaced 7 no-op TNC stubs with concrete runtime checks:
  - TNC-01 Authority Chain
  - TNC-03 Audit Continuity
  - TNC-04 Sync Constraints
  - TNC-05 Delegation Expiry
  - TNC-06 Conflict Disclosure
  - TNC-07 Quorum
  - TNC-09 AI Ceiling
  - TNC-10 Ratification
- Expanded `AuthorityLink` to carry actor kind, expiry, and conflict disclosure.
- Expanded `DecisionObject` to carry quorum, decision class, sync state, ratification, and human review metadata.
- Replaced hardcoded constitution placeholder with a real constitution catalog hash.
- Replaced misleading FRE 803(6) compliance claim with an explicit review-required note.
- Added structured audit logging for escalation and enforcement failures.
- Declared threshold values explicitly in the policy spec.
- Clarified that recursive SFT restrictions are process-level governance controls.

## Remaining Honest Limitation
- The GOV-001..013 and LEG-001..013 catalogs are now real hash-bound catalogs, but not every catalog item is yet a standalone runtime validator. The crate docs were updated to stop claiming otherwise.

## Verification
- `cargo test` in `crates/decision-forum`
- Council review + amendment pass
