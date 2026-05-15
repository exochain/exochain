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

# Gauntlet 0dentity Error Propagation Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-071 and F-072. The source artifacts remain imported evidence and were not
committed as source files:

- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md`
- `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv`

Validation target:

- branch: `main`
- commit: `ade233c3ae472c1dc1cbd4a81b88f77c3e66cb73`

## Path Classification

| Path family | Classification | Notes |
| --- | --- | --- |
| `crates/exo-node/src/zerodentity/onboarding.rs` | Core runtime adapter | 0dentity first-touch onboarding, OTP challenge, and identity-session write path. |
| `crates/exo-node/src/zerodentity/api.rs` | Core runtime adapter | 0dentity owner-session verification, peer-attestation write path, and read/error propagation guards. |
| `crates/exo-node/src/zerodentity/store.rs` | Core runtime adapter | In-process 0dentity store boundary used by the current node adapter. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-071 silent error discard on OTP challenge and session store writes | Stale / already remediated | `submit_claim` maps OTP challenge insertion errors through `store_error_response`; `verify_otp` updates the challenge and inserts the session inside one blocking store critical section, and both operations return closed errors through `store_error_response` instead of being ignored. |
| F-072 silent error discard on peer attestation insert | Stale / already remediated | `create_peer_attestation` persists the target claim and then calls `store.insert_attestation(&attestation).map_err(store_error)?`; the write path does not use a discarded `let _ =` result or `.ok()` conversion. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-node first_touch_submit_claim_propagates_otp_challenge_store_error -- --nocapture
cargo test -p exo-node verify_otp_consumes_challenge_and_session_in_one_store_lock -- --nocapture
cargo test -p exo-node api_handlers_do_not_discard_store_read_errors -- --nocapture
cargo test -p exo-node create_peer_attestation_success_with_message_hash -- --nocapture
```

## Notes

No production code change was required because the reported silent-discard
patterns did not reproduce against current `main`.
