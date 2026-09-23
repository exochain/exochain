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

# v0.3.0 release-gate index

The terminal release decision is the conjunction of every mandatory gate.
Unknown, pending, stale, mismatched, or rejected evidence evaluates as failure.

| Gate | Required result | Current state | Effect |
| --- | --- | --- | --- |
| G00 guard and evidence recovery | `G00_GUARD_AND_EVIDENCE_RECOVERY_VERIFIED` under exact operative directives | `NOT_ESTABLISHED_IN_TRACKED_RECORD` | `STOP` |
| Successor-plan authority and formal-input integrity | Separately authorized, byte-bound successor plan with all required approvals | `NOT_AUTHORIZED` | `STOP` |
| Open-issue integrity | Current-main issue intake; every release-integral issue reproduced, classified, resolved or adjudicated, tested, and independently approved | `INACTIVE` | `STOP` |
| EXO-DAG-DB inclusion | Separately authorized scope decision and all implementation, adapter, persistence, security, rollback, and evidence gates applicable to that decision | `INACTIVE` | `STOP` |
| Implementation TDD | RED first, minimal GREEN, focused and full required tests, mutation or bypass proof, exact evidence | `NOT_STARTED_UNDER_THIS_LANE` | `STOP` |
| Constitutional and council review | Required distinct reviewers unanimously approve one immutable candidate | `NOT_ESTABLISHED` | `STOP` |
| Repository quality gates | Build, test, coverage, lint, format, audit, deny, docs, cross-implementation, and any affected adapter gates pass on the exact candidate | `NOT_RUN_FOR_V0.3.0_CANDIDATE` | `STOP` |
| Evidence and provenance closure | Final manifest binds exact source, artifacts, commands, results, reviewers, hashes, modes, lengths, and external readbacks required by scope | `NOT_ESTABLISHED` | `STOP` |
| Release-operation authority | Separate explicit principal authority for the exact reviewed candidate and exact requested operations | `WITHHELD` | `STOP` |

## Gate evaluation

Current result:

`RELEASE_STOPPED_FAIL_CLOSED`

No gate may pass by inference from another gate. In particular:

- containment evidence does not establish G00;
- G00 does not authorize successor-plan authoring or source development;
- a merged fix does not establish current deployment or runtime behavior;
- a passing CI run does not establish council approval, evidence provenance,
  signing, publication, or release authority;
- issue closure does not prove remediation without the exact integrated code
  and tests; and
- release-bearing integration does not mean release-approved.

## Final transition rule

The Draft pull request must remain unmerged. A later transition may occur only
when every mandatory gate above is established against one immutable release
candidate and the Chair separately authorizes the exact merge, tag, signing,
publication, deployment, activation, GitHub Release, claim, or issuance
operations requested. Until then, every such operation remains prohibited.
