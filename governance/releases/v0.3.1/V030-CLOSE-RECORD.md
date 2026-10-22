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

# v0.3.0 close record — draft, inside the v0.3.1 release

**Status: DRAFT. Unsigned. Not approved. Not a close. GD-031-01 remains
PENDING. This document does not claim release readiness, and it does not
close v0.3.0.**

This file is the place the v0.3.0 close is recorded. It lives in
`governance/releases/v0.3.1/`. There is no separate `v0.3.0` tag, and this
draft does not create one. Path A (tag 0.3.0 on its own) is not the selected
shape.

The checklist this record will be read against is
[governance/releases/v0.3.0/GOAL.md](../v0.3.0/GOAL.md). The score of that
checklist on `a2667295` is [V030-CLOSE-ASSESSMENT.md](V030-CLOSE-ASSESSMENT.md).
That assessment is not this record. [DEMO.md](DEMO.md) treats `V030-CLOSE` as
a precondition of a later demonstration. This draft does not satisfy that
precondition.

## GD-031-01

| Field | Entry |
| --- | --- |
| Record | [GD-031-01](GOVERNANCE-DECISIONS.md) |
| Status | PENDING |
| Question this draft answers | Where is the v0.3.0 close recorded, and is there a separate `v0.3.0` tag? |
| Decision | |
| Conditions | |
| Rationale | |
| Dissent | |
| Date | |
| Signatures | |

The blank fields above are for the humans named on GD-031-01. An agent must
not write a decision, a signature, or a date into them. This draft does not
sign GD-031-01, does not write a name into Signatures, and does not mark
GD-031-01 approved.

## Proposed text awaiting signature

This text has no effect while GD-031-01 is PENDING. It is the draft a human
may adopt by filling the blank fields above. Until those fields are filled
by the named roles, the text authorizes nothing.

| Field | Proposed entry |
| --- | --- |
| Selected shape | Path B in [GOAL.md](GOAL.md). Milestone 1 of this release is the v0.3.0 close. |
| Where the close is recorded | This file, inside the 0.3.1 release. |
| Tag | There is no separate `v0.3.0` tag. A later publication, if authorized, is the v0.3.1 publication. #789 still requires two distinct release approvers for that publication. |
| What this text does not do | It does not approve GD-031-01. It does not authorize capabilities C1–C8. It does not claim that prerequisite rows P1–P8 hold. It does not close #810 or #813. It does not claim specification §19.6.1. |

Chief Executive ruling, 2026-10-22 at 4:00 PM ET, not a signature and not a
decision: path B. The v0.3.0 close is recorded inside the 0.3.1 release.
There is no separate v0.3.0 tag. The Signatures field stays empty. Status
stays PENDING. This record is not approved.

## What a signed close would still have to say

[ISSUES.md](ISSUES.md) drafts V030-M1-01 and V030-M1-02. They are not done.
The assessment scores rows 1, 2, 4, 5, 6, and 8 as already holding in source
on `a2667295`, row 3 as partial, and row 7 as a missing release sentence.
This draft does not convert those scores into a close.

Sentences reserved for the human who signs the close:

1. This close is milestone 1 of the v0.3.1 release. It is not a `v0.3.0` GitHub release and not a `v0.3.0` tag.
2. This release does not claim specification §19.6.1. Issue #810 stays open. This record adds no `cgr_trace` producer.
3. Issue #813 stays outside milestone 1 unless humans narrow it to the eight rows in the v0.3.0 goal.
4. Reserved for the signer, and not written here: a statement that the eight rows hold, including the payment-evidence digest in `exo-pdp` (row 3) and the non-claim in sentence 2 (row 7). Row 3 is still the open work in V030-M1-01.

Market issues in [ISSUES.md](ISSUES.md) stay blocked until a human records
that the eight rows hold and until the matching GD-031 records are signed.
GD-031-02, GD-031-03, and GD-031-10 stay PENDING. `coverage_claim` stays
`none`.
