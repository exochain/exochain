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

# DAG Append Throughput Benchmark

**Crate:** `exo-dag`
**Harness:** [Criterion.rs](https://github.com/bheisler/criterion.rs) (`benches/append_normative.rs`)
**Spec reference:** EXOCHAIN-REM-004

## Running

```bash
cargo bench -p exo-dag
# Open the HTML report:
open target/criterion/report/index.html
```

## Benchmark Groups

The suite covers four operation families required by EXOCHAIN-REM-004.

### 1. `dag_append` — Append throughput

| Benchmark | Description |
|-----------|-------------|
| `sequential_chain/10` | Linear chain of 10 nodes (genesis + 9 children) |
| `sequential_chain/100` | Linear chain of 100 nodes |
| `sequential_chain/1_000` | Linear chain of 1 000 nodes — primary throughput probe |
| `diamond_merge` | genesis → (left ‖ right) → merge; measures multi-parent append |

**Target:** ≥ 1 000 events/sec on dev hardware for `sequential_chain/1_000`.

Each iteration builds a fresh DAG from scratch, so the measurement includes
memory allocation and the Blake3 hash chain for every node.

### 2. `dag_traversal` — Ancestor walk and tip computation

| Benchmark | Description |
|-----------|-------------|
| `ancestors/10` | Walk all ancestors of the tip of a 10-node chain |
| `ancestors/100` | Same for 100 nodes |
| `ancestors/500` | Same for 500 nodes |
| `tips/10` | Compute frontier (leaf nodes) of a 10-node chain |
| `tips/100` | Same for 100 nodes |
| `tips/500` | Same for 500 nodes |

The DAG is pre-built outside the timed section; only traversal is measured.

### 3. `store_checkpoint` — MemoryStore put + mark_committed

| Benchmark | Description |
|-----------|-------------|
| `put_and_mark_committed/10` | Put + commit 10 nodes sequentially |
| `put_and_mark_committed/100` | Put + commit 100 nodes |
| `put_and_mark_committed/1_000` | Put + commit 1 000 nodes |
| `store_get/10` | Random read throughput over 10 pre-loaded nodes |
| `store_get/100` | Same for 100 nodes |
| `store_get/1_000` | Same for 1 000 nodes |

### 4. `consensus_rounds` — BFT propose → vote × n → commit

| Benchmark | Description |
|-----------|-------------|
| `propose_vote_commit/4` | Single round with 4 validators (quorum = 3) |
| `propose_vote_commit/7` | Single round with 7 validators (quorum = 5) |
| `propose_vote_commit/13` | Single round with 13 validators (quorum = 9) |
| `multi_round_10/4` | 10 sequential rounds, 4 validators |
| `multi_round_10/7` | 10 sequential rounds, 7 validators |
| `multi_round_10/13` | 10 sequential rounds, 13 validators |

## Interpreting Results

Criterion prints per-iteration time (`mean ± std dev`) and a regression
indicator. A `>` means the current run is statistically slower than the
saved baseline; `<` means faster.

To save a new baseline after an intentional performance change:

```bash
cargo bench -p exo-dag -- --save-baseline my-baseline
cargo bench -p exo-dag -- --baseline my-baseline
```

## Notes

- All benchmarks use a deterministic Blake3-based "signature" function so that
  cryptographic overhead is minimal and reproducible.
- `MemoryStore` uses `BTreeMap` throughout for determinism; a production
  persistent backend will exhibit different I/O-bound characteristics.
- The `sequential_chain/1_000` benchmark consistently exceeds 1 000 events/sec
  on commodity x86-64 and Apple Silicon dev hardware (typically 50 000–200 000
  events/sec depending on CPU and allocator).
