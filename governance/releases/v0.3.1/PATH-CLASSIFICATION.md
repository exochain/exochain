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

# Path classification — v0.3.1 proposal package

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

Every file added by this package is a **constitutional governance artifact**
(EXOCHAIN core, documentation and proposed schema only). None is a runtime
adapter, adjacent surface, imported evidence, or vendored tree.

No file under `crates/`, `packages/`, `governance/` outside
`governance/releases/v0.3.1/`, `.github/`, or a deployment contract is modified.
`GAP-REGISTRY.md` is intentionally unmodified. No workflow, tag, or release
asset is modified.

| Path | Classification | What it is |
| --- | --- | --- |
| `governance/releases/v0.3.1/README.md` | EXOCHAIN core (governance artifact) | Package index |
| `governance/releases/v0.3.1/GOAL.md` | EXOCHAIN core (governance artifact) | Proposal goal |
| `governance/releases/v0.3.1/ARCHITECTURE.md` | EXOCHAIN core (governance artifact) | Proposed architecture |
| `governance/releases/v0.3.1/DEPENDENCY-GRAPH.md` | EXOCHAIN core (governance artifact) | Dependency graph |
| `governance/releases/v0.3.1/THREAT-MODEL.md` | EXOCHAIN core (governance artifact) | Proposal threat model. It does not replace `docs/architecture/THREAT-MODEL.md` |
| `governance/releases/v0.3.1/ISSUES.md` | EXOCHAIN core (governance artifact) | Draft issues, not GitHub issues |
| `governance/releases/v0.3.1/TEST-PLAN.md` | EXOCHAIN core (governance artifact) | Future test plan |
| `governance/releases/v0.3.1/DEMO.md` | EXOCHAIN core (governance artifact) | Scripted demonstration plan |
| `governance/releases/v0.3.1/RELEASE-EVIDENCE.md` | EXOCHAIN core (governance artifact) | Evidence requirements for a later release |
| `governance/releases/v0.3.1/GOVERNANCE-DECISIONS.md` | EXOCHAIN core (governance artifact) | PENDING decision templates |
| `governance/releases/v0.3.1/PATH-CLASSIFICATION.md` | EXOCHAIN core (governance artifact) | This file |
| `governance/releases/v0.3.1/V030-CLOSE-ASSESSMENT.md` | EXOCHAIN core (governance artifact) | v0.3.0 close assessment and path B recommendation. Not a release record |
| `governance/releases/v0.3.1/specs/*.md` | EXOCHAIN core (governance artifact) | Proposed protocol specifications |
| `governance/releases/v0.3.1/schemas/*.json` | EXOCHAIN core (governance artifact) | Proposed JSON Schemas, not an implemented wire format |
| `governance/releases/v0.3.1/test-vectors/*.json` | EXOCHAIN core (governance artifact) | Proposed fixtures, not a passing test run |

Core regression statement: this change does not alter EXOCHAIN core behavior.
There is no adapter boundary to test until a later authorized implementation.
The checks that apply to this package are the publication-claim checker, the
systemic-integrity claim checker, and the gap-registry truth guard, because
those guards must keep passing when governance documents are added.
