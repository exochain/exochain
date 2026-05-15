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

# Gauntlet Edge-Case Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet edge-case findings adjacent to authority, DAG persistence, HLC,
consensus scoring, budget accounting, and pagination. The source artifacts
remain imported evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `19137fabfe470972e756bfd9319d9bef9be2c90b`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-authority/src/chain.rs` | EXOCHAIN core | Authority-chain permission checks and delegation validation. |
| `crates/exo-dag/src/pg_store.rs` | EXOCHAIN core | PostgreSQL persistence for canonical DAG nodes and committed heights. |
| `crates/exo-core/src/hlc.rs` | EXOCHAIN core | Deterministic Hybrid Logical Clock implementation. |
| `crates/exo-consensus/src/scoring.rs` | EXOCHAIN core | Consensus convergence and panel-confidence scoring. |
| `crates/exo-catapult/src/budget.rs` | EXOCHAIN core | Workspace Rust budget ledger with EXOCHAIN determinism contract. |
| `crates/exo-node/src/zerodentity/api.rs` | Core runtime adapter | Node API surface for identity claims and score-history pagination. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-103 `has_permission()` vacuous truth on empty authority chains | Stale / already remediated | `has_permission` now returns `false` for an empty `AuthorityChain`, and the focused regression test proves an empty chain grants no permission. |
| F-104 negative PostgreSQL timestamp decoded through `as u64` | Stale / already remediated | DAG Postgres decoding uses `u64::try_from` and `u32::try_from`, rejects negative storage values, and rejects values that cannot round-trip through PostgreSQL `BIGINT`. |
| F-108 browser `Date.now()` used as HLC source | Stale / already remediated | Production HLC code is caller-source driven and has a source guard rejecting host wall-clock and browser date APIs. |
| F-109 `calculate_convergence` dead code leaves match score at zero | Stale / already remediated | Current consensus scoring computes canonical claim-set overlap with deterministic `BTreeSet`s and is exercised through unit and property tests. |
| F-110 `BudgetLedger::total_spent()` overflow | Stale / already remediated | `total_spent` folds event amounts with `u64::saturating_add`, and the hard-stop regression test proves overflow saturates to `u64::MAX`. |
| F-111 unbounded `limit` / `offset` pagination conversion | Stale / already remediated | 0dentity API pagination rejects zero or oversized limits, rejects offsets above the configured ceiling, converts with `usize::try_from`, and has a source guard rejecting lossy `as usize` casts in claim listing. |

## Commands Run

All commands below completed with exit code 0.

```bash
git pull --ff-only origin main
cargo test -p exo-authority has_permission_empty_chain -- --nocapture
cargo test -p exo-dag --features postgres timestamp -- --nocapture
cargo test -p exo-core production_hlc_source_does_not_read_host_wall_clock -- --nocapture
cargo test -p exo-consensus convergence -- --nocapture
cargo test -p exo-catapult total_spent -- --nocapture
cargo test -p exo-node list_claims -- --nocapture
```

## Notes

No production code change was required for this slice because the reported
edge-case failures did not reproduce against current `main`.
