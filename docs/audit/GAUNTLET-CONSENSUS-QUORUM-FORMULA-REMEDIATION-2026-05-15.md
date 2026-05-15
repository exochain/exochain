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

# Gauntlet F-156 Consensus Quorum Formula Remediation - 2026-05-15

## Imported Evidence

- Source: Wally Fipps Gauntlet findings corpus.
- Finding: F-156, "BFT quorum_size formula equivalence unproven".
- Reported path: `consensus.rs:48-54`.
- Severity: Low.

The external corpus remains imported evidence. This remediation verifies the
claim against current owned source and commits only the source guard,
documentation/test update, and this audit record.

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `crates/exo-dag/src/consensus.rs` | EXOCHAIN core | DAG-BFT quorum math and representative formula regression test. |
| `tools/test_consensus_quorum_formula_docs.sh` | EXOCHAIN core CI/source guard | Prevents regression to undocumented quorum formula equivalence. |
| `docs/audit/GAUNTLET-CONSENSUS-QUORUM-FORMULA-REMEDIATION-2026-05-15.md` | Imported-evidence triage record | Captures disposition and validation evidence. |

## Verification

Current `main` implemented `n - ((n - 1) / 3)` and had representative quorum
size tests, but did not prove inline that the formula equals the strict
`> 2/3` threshold. The finding is valid as a documentation/proof gap, not a
runtime behavior bug.

## Remediation

- Added `tools/test_consensus_quorum_formula_docs.sh` before changing source.
- Documented the implemented formula:
  `quorum_size(n) = n - floor((n - 1) / 3)`.
- Documented its equivalence to `floor(2n / 3) + 1`, the minimum integer
  strictly greater than two thirds.
- Added the `n = 3k`, `n = 3k + 1`, and `n = 3k + 2` case proof inline.
- Added a representative regression test covering validator counts `1..=128`
  plus the empty-set boundary.

## TDD Evidence

RED:

```bash
bash tools/test_consensus_quorum_formula_docs.sh
# consensus quorum formula docs test failed: quorum_size docs must state the implemented formula
```

GREEN commands are recorded after remediation.

```bash
bash tools/test_consensus_quorum_formula_docs.sh
cargo test -p exo-dag quorum_size -- --nocapture
cargo test -p exo-dag consensus -- --nocapture
cargo test -p exo-dag -- --nocapture
cargo clippy -p exo-dag --all-targets -- -D warnings
cargo doc -p exo-dag --no-deps
cargo fmt --all -- --check
git diff --check
```
