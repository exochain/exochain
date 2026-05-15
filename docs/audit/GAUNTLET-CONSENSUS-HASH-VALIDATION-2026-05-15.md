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

# Gauntlet Consensus Hash Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-074. The source artifacts remain imported evidence and were not committed as
source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `9e0aad06f6c8c42c62ed86ecc717f2544863c2f0`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-consensus/src/round.rs` | EXOCHAIN core | Canonical hash input for deliberation rounds. |
| `crates/exo-consensus/src/record.rs` | EXOCHAIN core | Canonical hash input for deliberation results. |
| `crates/exo-consensus/src/commitment.rs` | EXOCHAIN core | Canonical hash input for model commitments. |
| `crates/exo-consensus/src/error.rs` | EXOCHAIN core | Typed consensus hashing error boundary. |
| `crates/exo-core/src/hash.rs` | EXOCHAIN core | Shared CBOR-backed structured hashing utility. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-074 `ciborium::into_writer().unwrap_or_default()` silently produces an empty hash used in consensus hashing | Stale / already remediated | The reported `schema.rs` file no longer exists. `round.rs`, `record.rs`, and `commitment.rs` call `exo_core::hash::hash_structured`, which serializes with CBOR and returns `Result<Hash256>` instead of defaulting on failure. `ConsensusError::HashSerialization` carries the failing context and source error. A source guard rejects `unwrap_or_default` in `round.rs` and `record.rs`. |

## Commands Run

All commands below completed with exit code 0.

```bash
rg -n "unwrap_or_default\\(|into_writer\\(|to_vec\\(|ciborium" crates/exo-consensus crates/exo-dag crates/exo-core crates/exo-gateway -g '*.rs'
cargo test -p exo-consensus hash -- --nocapture
```

## Notes

No production code change was required because the reported silent fallback did
not reproduce against current `main`.
