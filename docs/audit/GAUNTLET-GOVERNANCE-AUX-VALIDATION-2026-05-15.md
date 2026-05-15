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

# Gauntlet Governance Auxiliary Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet governance, role, and receipt findings. The source artifacts remain
imported evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `068468e8a6876a406b6317ba8e7ed14adf45d626`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-governance/src/clearance.rs` | EXOCHAIN core | Core clearance policy, registry, and assignment enforcement. |
| `crates/exo-authority/src/permission.rs` | EXOCHAIN core | Deterministic authority permission vocabulary and permission-set operations. |
| `crates/exo-gateway/src/server.rs` | Core runtime adapter | Builds adjudication context for gateway actions from authority-chain rows. |
| `crates/exochain-wasm/src/governance_bindings.rs` | Core runtime adapter | WASM governance clearance bridge. |
| `crates/exo-governance/src/quorum.rs` | EXOCHAIN core | Quorum roles, approval signatures, and independence attestations. |
| `command-base/app/services/governance.js` | Adjacent surface | CommandBase governance receipt and heuristic invariant-checking service; not the canonical Rust kernel. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-006 `ClearanceLevel` and `Permission` enums orphan | Stale / already remediated | `ClearanceLevel` is exercised by core clearance policies and the WASM governance bridge; `Permission` backs deterministic `BTreeSet` permission sets and authority-chain permission checks. |
| F-010 `build_adjudication_context` always returns `vote` permission | Stale / already remediated | Gateway adjudication context now derives permissions from authority-chain scope rows. Focused regression coverage proves a requested non-vote permission is not replaced by a synthesized `vote`. |
| F-040 `quorum::Role` has no purpose statement | Stale / already remediated | `Role::Observer` is documented as read-only, and quorum policy tests reject observers as required roles and exclude observer approvals from verified quorum counts. |
| F-042 governance receipts from regex scan of LLM output | Live adjacent finding; not an EXOCHAIN core finding | The report itself identifies `command-base/app/services/governance.js`. Current source still creates CommandBase receipts around heuristic invariant-check output. This does not exercise the Rust constitutional kernel or core receipt path, so this record does not close F-042. |
| F-043 `validateAgainstInvariants` regex patterns trivially evaded | Live adjacent finding; not an EXOCHAIN core finding | Current CommandBase source still validates untrusted output with regex and substring heuristics. This must remain isolated from core remediation and should be handled in a separate adjacent-surface change with CommandBase-specific tests. |
| F-044 `IndependenceAttestation.signature` never verified | Stale / already remediated | `IndependenceAttestation::verify_signature` verifies a canonical CBOR payload, `is_fully_valid` combines structure plus signature verification, and verified quorum tests reject empty, zero, wrong-key, tampered, missing, and unresolved signatures. |

## Commands Run

All commands below completed with exit code 0.

```bash
git fetch --prune origin
cargo test -p exo-governance clearance -- --nocapture
cargo test -p exo-authority permission -- --nocapture
cargo test -p exo-gateway adjudication_context_rows_derive_actor_permissions_from_authority_chain_scope -- --nocapture
cargo test -p exochain-wasm clearance -- --nocapture
cargo test -p exo-governance independence_attestation -- --nocapture
cargo test -p exo-governance observer -- --nocapture
cargo test -p exo-governance quorum -- --nocapture
node --test command-base/app/services/governance.test.js
```

## Notes

No EXOCHAIN core production code change was required for F-006, F-010, F-040,
or F-044 because those reported failures did not reproduce against current
`main`.

F-042 and F-043 remain classified as adjacent CommandBase findings. They must
not be represented as core constitutional-kernel failures, and this validation
record intentionally does not mark them remediated.
