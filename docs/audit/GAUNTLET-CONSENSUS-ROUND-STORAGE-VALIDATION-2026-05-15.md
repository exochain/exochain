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

# Gauntlet Consensus Round Storage Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-097. The source artifacts remain imported evidence and were not committed as
source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `ade233c3ae472c1dc1cbd4a81b88f77c3e66cb73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-consensus/src/session.rs` | EXOCHAIN core | Consensus deliberation session execution and finalization path. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-097 `execute_round` / finalization clones the full `rounds` history | Stale / already remediated | `DeliberationSession::finalize` consumes `self`, destructures `rounds`, and moves the full round history into `DeliberationResult`. A source guard rejects `self.rounds.clone()` in the finalization implementation and requires the consuming `pub fn finalize(self, ...)` signature. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-consensus production_finalization_moves_rounds_without_cloning_full_history -- --nocapture
cargo test -p exo-consensus finalize -- --nocapture
```

## Notes

No production code change was required because the reported full-round-history
clone during finalization did not reproduce against current `main`.
