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

# Gauntlet Admin Token Log Validation - 2026-05-15

This record preserves the current-main disposition for Wally Fipps Gauntlet
F-018. The source artifacts remain imported evidence and were not committed as
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
| `crates/exo-node/src/main.rs` | Core runtime adapter | Node startup path that creates and persists the privileged API bearer token. |
| `crates/exo-node/src/auth.rs` | Core runtime adapter | Bearer-token generation, persistence, redaction guard, and write/read authentication middleware. |
| `/private/tmp/exochain-gauntlet-findings/...` | Imported evidence | Read-only external assessment artifacts. |

## Disposition

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-018 admin bearer token logged at info level in plaintext on startup | Stale / already remediated | Startup no longer logs token material. `main.rs` writes the token only through `auth::write_admin_token_file` and logs that token material is omitted. `auth.rs` stores the bearer token in `Zeroizing<String>`, writes the token file with restrictive permissions, and includes a source guard rejecting `token_prefix` and `admin_token.chars().take` in production startup code. |

## Commands Run

All commands below completed with exit code 0.

```bash
cargo test -p exo-node startup_does_not_log_admin_token_material -- --nocapture
cargo test -p exo-node admin_token -- --nocapture
```

## Notes

No production code change was required because the reported plaintext startup
token log did not reproduce against current `main`.
