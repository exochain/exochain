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

# Versioning Policy

## Scheme

EXOCHAIN follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

```
MAJOR.MINOR.PATCH
```

- **MAJOR**: Breaking changes to the constitutional invariant API, BCTS state machine, or governance protocol
- **MINOR**: New crates, new governance features, new API surfaces (backward-compatible)
- **PATCH**: Bug fixes, documentation updates, dependency bumps (backward-compatible)

## Current Status

The workspace version is set in `Cargo.toml`:
```toml
[workspace.package]
version = "0.1.0"
```

## Release Process

See `.github/workflows/release.yml` for the automated release workflow:

1. All 9 CI quality gates must pass (ci.yml)
2. All 6 CR-001 release-specific gates must pass (release-gates job)
3. DualControl: two independent council-panel reviewers must approve via the GitHub `release` environment
4. Native artifacts built for `x86_64-linux-gnu` and `aarch64-linux-gnu`
5. WASM artifact built via `wasm-pack` for the `exochain-wasm` crate
6. GPG-signed tag created and pushed (secrets: `RELEASE_GPG_PRIVATE_KEY`, `RELEASE_GPG_PASSPHRASE`)
7. SHA-256 provenance manifest generated covering all release artifacts
8. GitHub Release created from the signed tag with all artifacts attached
9. Crates published to crates.io in dependency order (unless dry-run)
10. Post-publish smoke test verifies `exo-core` is downloadable and buildable

### Dry Run

Trigger via the GitHub Actions UI with `dry_run=true`. This runs all gates and builds
all artifacts but skips the signed tag push, crates.io publish, and smoke test.
The GitHub Release is created as a draft for review.

```bash
# Quick local validation (does not replicate the full release pipeline):
cargo build --workspace --release
cargo test --workspace
```

### DualControl Configuration

The `release` environment in GitHub repository settings **must** have at least two
required reviewers from distinct council panels before any live release. Dry-run
executions do not require this restriction. To configure:

> Repository Settings → Environments → release → Required reviewers → add ≥ 2 reviewers

## Rollback (Yank) Procedure

Once a version is published to crates.io it cannot be deleted, but it can be yanked
to prevent new projects from depending on it.

**When to yank:** defective API, security vulnerability, broken build, or council
resolution requiring retraction.

```bash
# Yank a specific crate version (repeats for each affected crate)
cargo yank --version 0.1.0 exo-core

# Restore a yank if issued in error
cargo yank --version 0.1.0 exo-core --undo
```

Yanks must be logged as a governance action: open an issue with label
`exochain:council-review` documenting the reason, the affected crates, and the
approving council panel before executing the yank.

GitHub Releases can be edited to mark a release as pre-release or can be deleted
(which does not remove the git tag). The signed tag itself should be retained for
audit-trail purposes even when a release is retracted.

## Constitutional Constraint

Per the ExistentialSafeguard invariant, **major version bumps** (breaking changes to constitutional invariants) require supermajority council approval. This is enforced by the ExoForge governance gate.

## Pre-1.0 Expectations

While at `0.x.y`:
- The public API surface may change between minor versions
- Constitutional invariants are stable but their enforcement mechanisms may evolve
- The BCTS state machine (14 states) is stable
- Cryptographic primitives (BLAKE3, Ed25519) are stable
