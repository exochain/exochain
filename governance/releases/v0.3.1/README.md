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

# EXOCHAIN v0.3.1 proposal package

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This package does not claim release readiness.**

This directory is the human review package for the v0.3.1 market-making
directive. It contains documents, proposed schemas, and proposed test-vector
fixtures. It contains no runtime code, no workflow edits, no tag, and no
publication change.

Normative rank follows [ADR-001](../../../docs/adr/ADR-001-authority-of-text.md):
EXOCHAIN Specification v2.2 is the normative specification. These files are
tier-4 repository governance artifacts. They do not amend the kernel, and they
do not outrank a ratified council resolution.

| Document | Role |
| --- | --- |
| [GOAL.md](GOAL.md) | Mission, eight capabilities, constraints, non-goals, v0.3.0 dependency, acceptance criteria |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Six-layer architecture and exists-versus-new map |
| [DEPENDENCY-GRAPH.md](DEPENDENCY-GRAPH.md) | Crate, module, and work-item graph, including v0.3.0 prerequisites |
| [THREAT-MODEL.md](THREAT-MODEL.md) | STRIDE across the six layers, plus the named abuse cases |
| [ISSUES.md](ISSUES.md) | Draft implementation issues. Not GitHub issues |
| [TEST-PLAN.md](TEST-PLAN.md) | Deterministic tests, conformance vectors, two-system demonstration |
| [DEMO.md](DEMO.md) | Scripted minimum demonstration and the artifacts it must produce |
| [RELEASE-EVIDENCE.md](RELEASE-EVIDENCE.md) | Evidence a future release would have to produce, and how to verify it |
| [GOVERNANCE-DECISIONS.md](GOVERNANCE-DECISIONS.md) | Blank decision records. Every record is PENDING |
| [PATH-CLASSIFICATION.md](PATH-CLASSIFICATION.md) | Classification of every file in this package |
| [V030-CLOSE-ASSESSMENT.md](V030-CLOSE-ASSESSMENT.md) | Item-by-item score of the v0.3.0 goal against `main` at `a2667295`, and the path B recommendation. Not a close |
| [specs/](specs/) | Protocol specifications |
| [schemas/](schemas/) | Proposed JSON Schemas |
| [test-vectors/](test-vectors/) | Proposed fixtures for a later conformance harness |

Baseline observed while writing this package:

- `main` at `a2667295e49bdf357f5ed53ff5ddef15ace5f727`.
- Git tag `v0.2.7` exists. The GitHub release `v0.2.7` was not a draft and not a
  prerelease when viewed on 2026-10-09 (`publishedAt` `2026-10-08T17:28:52Z`,
  <https://github.com/exochain/exochain/releases/tag/v0.2.7>).
- No `v0.3.0` tag exists in this checkout.
- CEO direction of 2026-10-09 (commercial lines preparatory; no assurance
  partner yet) is recorded on GD-031-02, GD-031-03, and GD-031-10. Those
  records stay PENDING signature. `coverage_claim` stays `none`.
- `governance/releases/published-release-snapshot.json` still records the last
  verified publication claim as v0.2.4, observed `2026-09-16T18:29:42Z`. This
  package does not amend that snapshot. A git tag is not, by itself, the
  repository's dated publication claim.

Gap ledger: proposed v0.3.1 work is **not** added to `GAP-REGISTRY.md`. That
file is the systemic-integrity execution ledger for VCG-001 through VCG-015,
guarded by `tools/test_gap_registry_truth.sh`. These proposal items are future
work, not newly discovered critical gaps on current `main`. Their tracking home
is [ISSUES.md](ISSUES.md). Open VCG rows still constrain what this proposal is
allowed to claim; see [GOAL.md](GOAL.md).
