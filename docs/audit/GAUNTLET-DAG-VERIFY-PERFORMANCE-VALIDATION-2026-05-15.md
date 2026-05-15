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

# Gauntlet DAG Verify Performance Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-095. The source artifacts remain imported evidence and were not committed as
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
| `crates/exo-dag/src/dag.rs` | EXOCHAIN core | Canonical in-memory DAG append, ancestor traversal, and node verification logic. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-095 `verify_node` calls `ancestors()` and materializes a full BFS/topological ancestor list per verification | Stale / already remediated | `verify_node` no longer calls `ancestors(dag, &node.hash)` or scans a materialized ancestor list. The current cycle guard calls `has_ancestor_path`, which uses parent reachability with early exit. A source guard rejects reintroducing the full ancestor-list verification path. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-dag verify_node_cycle_check_does_not_materialize_full_ancestor_list -- --nocapture
cargo test -p exo-dag ancestor_path_detection_uses_parent_reachability -- --nocapture
cargo test -p exo-dag verify_node -- --nocapture
```

## Notes

No production code change was required because the reported full-ancestor-list
verification path did not reproduce against current `main`.
