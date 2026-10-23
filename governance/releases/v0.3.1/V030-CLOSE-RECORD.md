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

# v0.3.0 close record — inside the v0.3.1 release

**Status: GD-031-01 SIGNED for path B, subject to its conditions.
Completion evidence for P1–P8 remains required. This document does not
claim release readiness or authorize a tag from PR #887.**

This file is the place the v0.3.0 close is recorded. It lives in
`governance/releases/v0.3.1/`. There is no separate `v0.3.0` tag, and this
record does not create one. Path A (tag 0.3.0 on its own) is not the selected
shape.

The checklist this record will be read against is
[governance/releases/v0.3.0/GOAL.md](../v0.3.0/GOAL.md). The score of that
checklist on `a2667295` is [V030-CLOSE-ASSESSMENT.md](V030-CLOSE-ASSESSMENT.md).
That assessment is not this record. [DEMO.md](DEMO.md) treats `V030-CLOSE` as
a precondition of a later demonstration. Signing the release shape does
not by itself satisfy that precondition's completion-evidence requirement.

## GD-031-01

| Field | Entry |
| --- | --- |
| Record | [GD-031-01](GOVERNANCE-DECISIONS.md) |
| Status | SIGNED |
| Question this record answers | Where is the v0.3.0 close recorded, and is there a separate `v0.3.0` tag? |
| Decision | Path B: the v0.3.0 close is written in `V030-CLOSE-RECORD.md`, inside the 0.3.1 release. There is no separate `v0.3.0` tag. |
| Conditions | This decision records the close location and release shape. Completion evidence for P1–P8 remains required before implementation of C1–C8; other required GD-031 records remain pending. Do not create a `v0.3.0` or `v0.3.1` tag from PR #887. Publication still requires the two distinct release-environment approvers under #789. |
| Rationale | Adopt the assessed path B so the v0.3.0 close is milestone 1 of v0.3.1, with one release record and no separate v0.3.0 publication cycle. Preserve the prerequisite evidence and publication controls. |
| Dissent | None recorded. |
| Date | 2026-10-23 |
| Signatures | Bob Stewart — Chief Executive, EXOCHAIN PBC (`bob-stewart`); Max Stewart — Release approver A (`mstewartbz`, `release`); Robert Stewart — Release approver B (`robst3w`, `release-second`). |

The three human names above are transcribed at the Chief Executive's
explicit instruction on 2026-10-23, naming Max and Robert as the two release
approvers. PR #887 also records approvals by `robst3w` on 2026-10-22 at
20:23:54 UTC and `mstewartbz` at 20:29:50 UTC. This transcription is not an
agent approval or a release-environment approval.

## Recorded scope

GD-031-01 is signed for the path B release shape. The conditions above
preserve the completion-evidence requirements and publication controls.

| Field | Entry |
| --- | --- |
| Selected shape | Path B in [GOAL.md](GOAL.md). Milestone 1 of this release is the v0.3.0 close. |
| Where the close is recorded | This file, inside the 0.3.1 release. |
| Tag | There is no separate `v0.3.0` tag. Neither a `v0.3.0` nor a `v0.3.1` tag may be created from PR #887. A later publication, if separately authorized, still requires two distinct release approvers under #789. |
| What this decision does not do | It does not authorize capabilities C1–C8 before the required close evidence and other decisions. It does not claim that prerequisite rows P1–P8 hold. It does not close #810 or #813. It does not claim specification §19.6.1. |

The Chief Executive's 2026-10-22 4:00 PM ET path B ruling is background,
not a signature. The dated Signatures field above records the three names;
the ruling does not substitute for it.

## Completion evidence still required

[ISSUES.md](ISSUES.md) drafts V030-M1-01 and V030-M1-02. They are not done.
The assessment scores rows 1, 2, 4, 5, 6, and 8 as already holding in source
on `a2667295`, row 3 as partial, and row 7 as a missing release sentence.
Signing GD-031-01 does not convert those scores into completion evidence.

Completion statements required in addition to the signed release shape:

1. This close is milestone 1 of the v0.3.1 release. It is not a `v0.3.0` GitHub release and not a `v0.3.0` tag.
2. This release does not claim specification §19.6.1. Issue #810 stays open. This record adds no `cgr_trace` producer.
3. Issue #813 stays outside milestone 1 unless humans narrow it to the eight rows in the v0.3.0 goal.
4. Reserved for the signer, and not written here: a statement that the eight rows hold, including the payment-evidence digest in `exo-pdp` (row 3) and the non-claim in sentence 2 (row 7). Row 3 is still the open work in V030-M1-01.

Market issues in [ISSUES.md](ISSUES.md) stay blocked until a human records
that the eight rows hold and until the matching GD-031 records are signed.
GD-031-02, GD-031-03, and GD-031-10 stay PENDING. `coverage_claim` stays
`none`.
