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

# v0.3.0 workstream index

All workstreams are release-bearing when lawfully integrated, but none may
infer authority from this index. Development and verification roles must
remain separate. Production changes require strict RED-first TDD, the smallest
sufficient GREEN implementation, focused verification, relevant full gates,
bypass-class review, and exact evidence.

| Workstream | Class | Current state | Entry condition | Integration condition |
| --- | --- | --- | --- | --- |
| G00 guard and evidence recovery | EXOCHAIN core governance and release guard | `ACTIVE_ONLY_UNDER_ISSUED_RECOVERY_DIRECTIVES; RESULT_NOT_ESTABLISHED_HERE` | Exact issued G00 authority | Required distinct unanimous G00 approvals on one frozen commit and guard tuple |
| Canonical release integration | EXOCHAIN core governance artifacts | `DOCUMENTATION_LANE_AUTHORIZED` | Chair's GitHub integration authority | Independent scope, evidence-hygiene, and Git verification; Draft PR only |
| Open-issue integrity intake | Imported evidence moving to classified remediation | `PRESERVED_INACTIVE` | `G00_GUARD_AND_EVIDENCE_RECOVERY_VERIFIED` plus separate authoring or development authority | Current-main reproduction, owned-path classification, strict TDD, applicable gates and council approvals |
| EXO-DAG-DB inclusion assessment | Core runtime adapter planning intake | `PRESERVED_INACTIVE` | `G00_GUARD_AND_EVIDENCE_RECOVERY_VERIFIED` plus separate authoring or development authority | Anti-duplication review, trust-boundary proof, strict TDD, adapter and core gates, applicable council approvals |
| Formal successor plan | EXOCHAIN core governance artifact | `PROHIBITED` | Lawful G00 completion plus separate principal authority | Exact formal-input validation and required unanimous approval |
| Source and test implementation | To be classified per changed path | `NOT_AUTHORIZED_BY_THIS_LANE` | Separate bounded workstream authority | RED evidence, GREEN evidence, full required gates, independent review, exact integration decision |
| Release ceremony and delivery | Release operation | `PROHIBITED` | Every mandatory gate complete plus separate explicit principal authority | Exact reviewed commit, signed artifacts where authorized, publication and deployment evidence |

## Open-issue integrity requirements

The open-issue intake is integral to the v0.3.0 objective once activated. It
must be refreshed against current `main` and current GitHub state under its own
authority. Each finding must be classified as EXOCHAIN core, core runtime
adapter, adjacent surface, imported evidence, or third-party/vendor; reproduced
before remediation; bound to an owned runtime path; and resolved or explicitly
adjudicated before the corresponding release gate may pass.

Issue closure, a pull-request label, or a conversational statement is not proof
of remediation. The exact integrated commit, tests, and current issue state
must agree.

## EXO-DAG-DB requirements

EXO-DAG-DB inclusion is mandatory successor-planning intake, not currently
authorized implementation. Activation must preserve EXOCHAIN as the canonical
substrate, apply the repository's anti-duplication and runtime-adapter rules,
define exact ownership and trust boundaries, prove fail-closed behavior, and
separately validate runtime, persistence, RLS, canary, observability, and
rollback claims applicable to the chosen scope.

No external repository import, dependency change, code copy, bridge, API,
schema, migration, or production activation is authorized by this record.

## Per-workstream handoff

Every future integration request must identify:

- authority identifier and exact scope;
- isolated branch and immutable base;
- changed-path classification;
- RED test and observed failure;
- minimal GREEN implementation and observed pass;
- focused, workspace, security, bypass, determinism, and documentation checks
  required by the affected boundary;
- writer identity and distinct reviewer identities;
- exact head, tree, changed paths, file modes, digests, and byte lengths; and
- an explicit integrate, reject, or stop decision.
