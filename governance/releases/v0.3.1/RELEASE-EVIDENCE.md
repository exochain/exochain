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

# Release evidence requirements

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release. This document does not claim release readiness.**

This file lists what a future v0.3.1 release would have to produce and how a
reviewer would verify it. This pull request produces none of that runtime
evidence. The presence of this file is not evidence.

## What this pull request is allowed to count as

| Item | How to verify |
| --- | --- |
| The proposal text, schemas, and vectors | Diff limited to `governance/releases/v0.3.1/` |
| Decision records still PENDING | Every status cell in `GOVERNANCE-DECISIONS.md` reads PENDING |
| No publication-claim edit | `governance/releases/published-release-snapshot.json` and the README publication row are untouched |
| No v0.3.0 or v0.3.1 tag created by this change | `git tag` and the release workflow files are untouched |
| Guards | `python3 tools/check_published_release_claim.py`, `bash tools/check_systemic_integrity_claims.sh`, `bash tools/test_gap_registry_truth.sh` exit 0 |

## What a later release record would have to include

A release record is a separate human artifact. It is not created here.

| Evidence | Verifier | Fails if |
| --- | --- | --- |
| v0.3.0 close record covering P1–P8 | Read the record against `governance/releases/v0.3.0/GOAL.md` | Any prerequisite is "in source since 0.2.4" with no close |
| GD-031-01 through GD-031-11 filled, signed by the named roles, no agent DID among signers | Compare roles to the filled signature blocks | Any record still PENDING, or one person signed both release environments |
| #789 environments | The release workflow run shows two distinct approvers, self-review off | One approver, or the committing agent is an approver |
| Demonstration directory from `DEMO.md` | Recompute BLAKE3 of `08-evidence-bundle.cbor` and compare to the stamp imprint inputs | Missing file, or a private key in the directory |
| Second-verifier log | Confirm the process argv and the file list | The verifier linked the workspace or received a credential |
| Conformance vector results | Both systems' decision lines match | Any mismatch |
| Feature flag default | Cargo features and a default-feature test | The market path is on without the flag |
| Non-coverage scan | The guard from V031-F02 | A forbidden phrase in the release notes |
| No spec §19.6.1 claim | Read the release notes | The notes claim CGR completeness |
| No take-rate | Read the charged amount on the demo policy | A platform fee appears while GD-031-02 does not authorize one |

## How verification stays reproducible

Reviewers re-hash artifacts. They do not accept a screenshot of a dashboard
as the bundle. They do not accept an agent's summary as the second verifier.
Git tags remain insufficient as publication evidence. The dated publication
snapshot is updated only by the existing publication process, in a change
that is not this proposal.

## Explicit non-claims

This package does not claim:

- release readiness;
- a v0.3.0 close;
- a v0.3.1 tag;
- Microsoft approval or a Microsoft contract;
- insurance, surety, bonding, or reinsurance;
- that MCP execution is constitutional adjudication;
- production zero-knowledge soundness;
- that 0dentity device or behavior signals are in the market trust path.
