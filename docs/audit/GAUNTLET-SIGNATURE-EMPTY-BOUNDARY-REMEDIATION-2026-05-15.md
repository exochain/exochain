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

# Gauntlet F-155 Signature::Empty Boundary Remediation - 2026-05-15

## Imported Evidence

- Source: Wally Fipps Gauntlet findings corpus.
- Finding: F-155, "Signature::EMPTY boundary implicit".
- Reported path: `types.rs:311-320`.
- Severity: Medium.

The external corpus remains imported evidence. This remediation verifies the
claim against current owned source and commits only the source guard,
documentation update, and this audit record.

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `crates/exo-core/src/types.rs` | EXOCHAIN core | Canonical signature type and sentinel boundary docs. |
| `crates/exo-core/src/crypto.rs` | EXOCHAIN core | Existing verification path explicitly rejects `Signature::Empty`; unchanged. |
| `tools/test_signature_empty_boundary_docs.sh` | EXOCHAIN core CI/source guard | Prevents regression to implicit sentinel-boundary docs. |
| `docs/audit/GAUNTLET-SIGNATURE-EMPTY-BOUNDARY-REMEDIATION-2026-05-15.md` | Imported-evidence triage record | Captures disposition and validation evidence. |

## Verification

Current `main` already had the important runtime behavior:

- `crypto::verify` returns `false` for `Signature::Empty`.
- `Signature::as_bytes()` panics for `Signature::Empty` instead of returning a
  zero sentinel.
- Existing tests cover empty-signature rejection and non-Ed25519 downgrade
  prevention.

The remaining live issue was documentation: the `Signature::Empty` type docs did
not spell out when the sentinel is acceptable and when it is a security
violation.

## Remediation

- Added `tools/test_signature_empty_boundary_docs.sh` before changing docs.
- Documented `Signature::Empty` as an unsigned construction sentinel.
- Documented that it is acceptable only before a value reaches a trust boundary.
- Documented that it must be rejected before persistence, verification,
  authorization, consensus, or trust-record finalization.
- Documented that `is_empty()` is only a structural null-sentinel check and must
  not be treated as proof that a non-empty signature is valid.

## TDD Evidence

RED:

```bash
bash tools/test_signature_empty_boundary_docs.sh
# Signature::Empty boundary docs test failed: types.rs must define Signature::Empty as an unsigned construction sentinel
```

GREEN:

```bash
bash tools/test_signature_empty_boundary_docs.sh
cargo test -p exo-core signature_empty -- --nocapture
cargo test -p exo-core signature_as_bytes -- --nocapture
cargo test -p exo-core signature -- --nocapture
cargo test -p exo-core crypto::tests:: -- --nocapture
cargo test -p exo-core -- --nocapture
cargo clippy -p exo-core --all-targets -- -D warnings
cargo doc -p exo-core --no-deps
cargo fmt --all -- --check
git diff --check
```
