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

# Gauntlet Crypto Canonical Validation - 2026-05-15

This record preserves the current-main disposition for selected Wally Fipps
Gauntlet cryptographic hashing findings. The source artifacts remain imported
evidence and were not committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `28e8e8c7cba64633b8de31b39af7bc1701801c73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-core/src/hash.rs` | EXOCHAIN core | Canonical structured hashing and Merkle helpers. |
| `crates/exo-core/src/types.rs` | EXOCHAIN core | `SecretKey` equality and `TrustReceipt` signing/hash payloads. |
| `crates/exo-governance/src/custody.rs` | EXOCHAIN core | Custody event hash construction and integrity verification. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-024 dual hash primitive using `serde_cbor` instead of canonical `ciborium` | Stale / already remediated | No current owned Rust source or lockfile entry references `serde_cbor`. Core structured hashes use `hash_structured`, which serializes through `ciborium::into_writer` before BLAKE3 hashing. |
| F-026 Merkle tree lacks leaf/interior domain separation | Stale / already remediated | `merkle_root` hashes leaves in domain `0x00` and parent nodes in domain `0x01`; tests reject the legacy raw `H(left || right)` construction. |
| F-027 `TrustReceipt` signing payload uses ambiguous raw concatenation | Stale / already remediated | `TrustReceipt::payload_for_signature` emits a domain-tagged canonical CBOR payload, and the receipt hash path uses `hash_structured`. |
| F-028 `CustodyChain::compute_event_hash` falls back to `Hash256::ZERO` on CBOR failure | Stale / already remediated | `compute_event_hash` returns `Result<Hash256, CustodyChainError>` and maps CBOR/hash failures to `HashEncodingFailed`; source guards reject raw BLAKE3 loops and zero-hash fallback. |
| F-029 `SecretKey::PartialEq` is non-constant-time | Stale / already remediated | `SecretKey::eq` delegates to `constant_time_eq_32` and source guards reject short-circuiting slice equality for secret keys. |

## Commands Run

All commands below completed with exit code 0 unless explicitly noted.

```bash
git fetch --prune
git pull --ff-only
rg -n "serde_cbor" crates packages tools Cargo.toml Cargo.lock
cargo test -p exo-core --lib -- --nocapture
cargo test -p exo-governance custody -- --nocapture
```

`rg -n "serde_cbor" ...` completed with exit code 1 because there were no
matches in the searched current-main owned source, manifest, or lockfile paths.

## Notes

The same Gauntlet secrets slice also references `command-base/app/server.js` and
`command-base/app/lib/auth.js` for F-003 and F-011. Those paths are adjacent
surface code, not EXOCHAIN core. They remain candidates for adjacent-surface
validation or hardening after live core and core-runtime-adapter findings are
settled.
