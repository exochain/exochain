---
title: "Beta repository maintainer ownership correction"
status: proposed
created: 2026-09-24
tags: [governance, beta, maintainers, review]
---
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

# Beta repository maintainer ownership correction

## Proposal and scope

Bob Stewart requested preparation of a reviewed correction naming Bob Stewart
(`@bob-stewart`), Max Stewart (`@mstewartbz`), and Robert (`@robst3w`) as the
responsible repository maintainers for Architecture, Governance, and Operations.
He subsequently clarified that he is accountable for security and legal/compliance
matters, that security audits use Daybreak plus other review systems, and that
there is no separate Legal department or Legal role in the beta organization.
This records a proposed beta operating arrangement, not completed human review
or ratification. It becomes effective prospectively only through properly
reviewed integration of this correction; its PR records the actual approvals,
final candidate, CI results, and integration identity.

The unresolved team references are replaced with the named real reviewer
accounts, including security-sensitive and legal/compliance paths. Existing path
patterns and precedence are retained. Bob remains accountable for security and
legal/compliance; Max and Robert remain independent maintainer reviewers, not
fictional departmental staff. This replaces the nonexistent team approval model
with substantive audit evidence and accountable human review. The roster applies to
repository implementation control only, not runtime authority or constitutional
council membership; it does not ratify other draft charters or resolutions.

## Review and trust boundaries

The two-maintainer review requirement remains in force. Two distinct independent
humans, excluding the PR author, must approve the final candidate before merge.
One person counts once, regardless of how many areas they cover. Because all
three maintainers cover all three named areas, their review can cover those
areas together without manufacturing additional independent reviewers. A
qualified or partial review must state its limits. Agent reviews cannot supply
either human approval.

Security-sensitive changes, including changes to `exo-core`, `exo-gatekeeper`,
or `exo-consent`, require security audit evidence and human review of its findings
before merge. Evidence may come from Daybreak and other security review systems;
no single system is an exclusive or mandatory provider. Record source revision,
scope, findings, remediation/disposition, and verification. Existing relevant
audits may be reused when applicability is demonstrated; ownership-document
changes alone do not require repeating completed audits. Bob is accountable for
finding disposition, which the independent maintainer reviewers verify. His
disposition on a Bob-authored PR cannot count as an independent review. Tool
output cannot supply a human approval or conceal an unresolved security finding.

There is no separate Legal department approval. Bob is accountable for applicable
legal/compliance matters and the maintainers review the evidence. Existing
license, dependency, consent, privacy, and other applicable compliance checks
remain; this does not make maintainers legal professionals or supply a legal
opinion. GitHub CODEOWNERS routes review; its multiple-owner alternatives and
last-matching-rule behavior do not implement the entire written approval policy.

This proposal changes no access permissions, branch/environment protections,
publisher secrets, runtime consent, signatures, or authority chains. The eight
runtime invariants and deterministic Rust behavior are unchanged. In particular,
the named roster cannot self-grant runtime power, replace legitimate independent
quorum, or substitute claimed approval for verifiable provenance. No production
code, dependency lock, original release payload, custody manifest, publication
identity pin, recovery expiry check, or release/retirement workflow is changed.
CI adds only a required source routing check; existing jobs remain required.

The main risks are routing review to nonexistent teams, treating tool output as
approval, counting one human several times, and confusing review routing with
release authority. Explicit accountability, preserved area paths, mutation-tested
routing, and substantive audit/human-review boundaries address those risks.
Releases remain subject
to exact-source CI, signing, protected human gates, fresh custody/expiry checks,
separate dry/live runs, and independent all-provider acceptance.

## PR841 chronology is not waived

PR841 candidate `0f6b154330dde8d0c4b48f1751142a7a1bdb38fb` was squash merged by
Bob at **2026-09-24 18:50:25 UTC** as
`019226edd0d7a9d825462a1ad180efe7eb61ce78`. Its 74 exact-head CI checks succeeded,
and the integrated tree equals the candidate tree. Those facts are not approval.

- [Max's review](https://github.com/exochain/exochain/pull/841#pullrequestreview-5308850532)
  approved the exact candidate at **18:59:25 UTC**.
- [Robert's review](https://github.com/exochain/exochain/pull/841#pullrequestreview-5308969853)
  approved the exact candidate at **19:10:24 UTC**.

Both are genuine recorded post-merge reviews. This correction neither backdates
them nor declares the recovery plan's pre-merge condition satisfied. It supplies
no retrospective waiver, successor maintenance tag, workflow dispatch, package
reupload, artifact-expiry exception, or retirement authorization. A successor
release controller must have its own genuine exact-head human approvals and CI
before normal integration, then satisfy every applicable protected release gate.
That prospective reviewed integration does not rewrite PR841's history.

## Validation and adoption checklist

- Reproduce the source-contract rejection against the original team mappings,
  then accept the corrected routing and reject mutations removing/duplicating a
  maintainer, introducing an unknown delegate, restoring a stale panel team,
  restoring nonexistent Security/Legal teams, dropping CI routing, or
  shadowing/reordering the explicit area rules:
  `bash tools/test_beta_codeowners.sh`.
- Independently compare all original patterns/order and confirm that every review
  route names the three real maintainers. Review Bob's accountability, tool-agnostic
  audit evidence, unchanged independent-review threshold, and compliance boundaries.
  Inspect the whole diff for permission, runtime, or release changes.
- Run the normal core gates and applicable recovery/retirement and CI source
  guards. Preserve failed and successful evidence separately. The static guard
  is not evidence of account access, live code-owner resolution, or human review.
- Freshly verify the three actual accounts' repository write access and GitHub
  CODEOWNERS validation on the pushed candidate; all owner entries must resolve.
- Obtain genuine independent exact-head human reviews and required CI before
  normal integration. If existing protections or governing authority prevent
  adoption, stop and request legitimate resolution; never bypass them.

All changed paths are **EXOCHAIN core** repository governance/CI controls. The
correction is isolated from product and adjacent-surface changes. Rollback is a
normally reviewed revert of this correction, preserving review history; do not
disable protections or silently restore invalid routing to force a release.
