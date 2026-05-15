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

# Gauntlet Governance Invariants Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet governance, role-fidelity, and compliance-report findings. The source
artifacts remain imported evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `28e8e8c7cba64633b8de31b39af7bc1701801c73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-gatekeeper/src/tee.rs` | EXOCHAIN core | TEE attestation policy and hardware quote verification boundary. |
| `crates/exo-gatekeeper/src/types.rs`, `crates/exo-gatekeeper/src/invariants.rs` | EXOCHAIN core | Governed role names and separation-of-powers enforcement. |
| `crates/exo-governance/src/clearance.rs`, `crates/exo-governance/src/quorum.rs` | EXOCHAIN core | Clearance assignment and quorum eligibility. |
| `crates/exo-authority/src/chain.rs`, `crates/exo-authority/src/delegation.rs` | EXOCHAIN core | Authority delegation records and grant validation. |
| `crates/exo-legal/src/compliance_report.rs` | EXOCHAIN core | Compliance attestations over core invariant evidence. |
| `crates/exochain-wasm/src/governance_bindings.rs` | Core runtime adapter | WASM bridge for governance clearance checks. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-033 TEE attestation is self-signed BLAKE3, not hardware attestation | Stale / already remediated | Synthetic signatures are accepted only for `TeePlatform::Simulated` in `TeeEnvironment::Testing`. Hardware platforms with synthetic signatures are rejected before verifier dispatch; non-synthetic hardware attestations fail closed unless an explicit `TeeQuoteVerifier` is supplied. |
| F-035 `Role.name` is unconstrained and weakens SeparationOfPowers | Stale / already remediated | `GovernedRoleName` is a finite enum. `Role::validate_governed` rejects unknown names and branch mismatches, and the invariant engine exercises those failures. |
| F-036 `ClearanceRegistry::set_level` has no caller guard, audit, or ceiling | Stale / already remediated | No public `set_level` API exists in current production source. `assign_level` rejects self-grants, requires Governor assigner clearance, enforces a superior-clearance ceiling, and appends audit evidence before mutation. |
| F-037 `wasm_check_clearance` hardcodes Governor clearance for every caller | Stale / already remediated | The WASM binding parses a caller-supplied verified clearance registry and denies a low-clearance actor in the focused bridge regression. |
| F-038 `Observer` accepted into quorum count | Stale / already remediated | `role_counts_toward_quorum` excludes `Role::Observer`; quorum policies reject Observer as a required role, and verified quorum excludes Observer approvals from total count. |
| F-039 `DelegateeKind::Unknown` assignable to new delegations | Stale / already remediated | `DelegateeKind::Unknown` remains only as a legacy deserialization default. `DelegationRegistry::delegate_signed_with` rejects it for new grants. |
| F-041 Compliance report hardcodes `Compliant` for every invariant | Stale / already remediated | `derive_status_and_evidence` produces `Gap`, `NotApplicable`, or `Compliant` from transparency-report evidence. Action-dependent invariants are not attested for empty periods, and nonzero action periods without MCP outcomes mark provenance as a gap. |

## Commands Run

All commands below completed with exit code 0.

```bash
git fetch --prune
git pull --ff-only origin main
cargo test -p exo-gatekeeper tee -- --nocapture
cargo test -p exo-gatekeeper separation_rejects -- --nocapture
cargo test -p exo-governance clearance_assignment -- --nocapture
cargo test -p exo-governance governor_assignment_updates_registry_and_appends_audit_entry -- --nocapture
cargo test -p exo-governance observer -- --nocapture
cargo test -p exo-authority delegate_rejects_unknown_delegatee_kind_for_new_grants -- --nocapture
cargo test -p exochain-wasm wasm_governance_bindings_registry_denies_low_clearance_actor -- --nocapture
cargo test -p exo-legal compliance_report -- --nocapture
git diff --check
```
