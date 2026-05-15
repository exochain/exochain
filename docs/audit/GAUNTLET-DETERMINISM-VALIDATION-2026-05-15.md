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

# Gauntlet Determinism Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet determinism and numeric-safety findings. The source artifacts remain
imported evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `19137fabfe470972e756bfd9319d9bef9be2c90b`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-governance/src/crosscheck.rs` | EXOCHAIN core | Cross-identity coordination and Sybil-adjacent governance checks. |
| `crates/exochain-wasm/src/*_bindings.rs` | Core runtime adapter | WASM bridge for core governance, consent, authority, messaging, and related APIs. |
| `crates/exo-node/src/mcp/tools/consent.rs` | Core runtime adapter | MCP consent tools exposed by the node runtime. |
| `crates/exo-node/src/zerodentity/scoring.rs` | Core runtime adapter | Node identity scoring logic feeding trust decisions. |
| `crates/exo-legal/src/bundle.rs` | EXOCHAIN core | Evidence bundle event indexing and canonical bundle assembly. |
| `crates/exo-core/src/types.rs` | EXOCHAIN core | Core `Version` counter semantics. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-100 `HashMap` / `HashSet` in Sybil and WASM paths | Stale / already remediated | `crosscheck.rs` uses `BTreeMap` and `BTreeSet`; WASM binding paths use deterministic collections and include a source guard rejecting `HashMap` and `HashSet` in the relevant bridge files. |
| F-101 floating-point scoring arithmetic despite deterministic workspace rules | Stale / already remediated | `zerodentity::scoring` uses basis-point integers plus `int_ln_milli` and `isqrt`; focused tests cover deterministic recompute, integer approximations, and the source guard for unchecked collection-count casts. |
| F-102 floating-point consent duration conversion in the MCP consent tool | Stale / already remediated | `exochain_propose_bailment` no longer fabricates a bailment in the default MCP context. It refuses with `mcp_consent_store_unavailable`; the schema accepts integer `duration_hours` only. |
| F-105 unchecked `usize` to `u32` event index truncation | Stale / already remediated | `idx_u32` uses `u32::try_from` and returns a typed legal error when an event index exceeds the sequence range. |
| F-106 `Version::next` overflow wraparound | Stale / already remediated | `Version::checked_next` reports overflow with `None`, and `Version::next` saturates at `Version::MAX` instead of wrapping. |
| F-107 unchecked numeric casts in identity scoring | Stale / already remediated | Scoring conversions use explicit saturating helpers built on `try_from`, and tests prove extreme counts clamp rather than truncate. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-governance crosscheck -- --nocapture
cargo test -p exo-node scoring -- --nocapture
cargo test -p exo-node propose_bailment -- --nocapture
cargo test -p exo-legal idx_u32 -- --nocapture
cargo test -p exo-core version -- --nocapture
cargo test -p exochain-wasm deterministic_collections -- --nocapture
```

## Notes

No production code change was required for this slice because the reported
determinism failures did not reproduce against current `main`.
