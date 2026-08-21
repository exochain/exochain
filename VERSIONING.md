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
version = "0.2.4"
```

The published release is `v0.2.4`: PDP decides, AVC records, x402 adapts;
crates.io `ml-dsa` consumers can build. Workspace version alignment is not
by itself evidence of a later tag, GitHub Release, registry publication,
deployment, or live runtime activation.

## Release Process

See `.github/workflows/release.yml` for the automated release workflow:

1. The full CI workflow, including the numbered constitutional gates and required aggregator, must pass.
2. Every dispatch traverses two independent GitHub environments (`release` and `release-second`) with distinct required reviewers. One environment is one-of; two environments are two-of. Repository settings, not workflow source, determine the reviewer lists.
3. Non-dry-run releases must have an existing, verifiable signed `v<version>` tag before artifacts build or publish.
4. Native artifacts are built for `x86_64-linux-gnu` and `aarch64-linux-gnu`.
5. Non-dry-run releases generate CycloneDX workspace SBOMs and GitHub SLSA build attestations via OIDC/Sigstore.
6. Non-dry-run releases publish crates in dependency order and publish the versioned npm packages after their dry-pack gates pass.
7. Non-dry-run release artifacts and SBOMs are attached to the existing signed `v<version>` tag in a published GitHub Release.

### Release Signing Key Setup

Live releases require an approved OpenPGP signing key controlled by the release
maintainer. The public key and full fingerprint must be configured as repository
variables so the release workflow can import the key on the GitHub runner before
executing `git tag -v`.

Create the signing key locally:

```bash
gpg --quick-generate-key "Bob Stewart EXOCHAIN Release Signing <bob@bobstewart.com>" ed25519 sign 2y
```

Record the full fingerprint and export the public key:

```bash
RELEASE_SIGNING_UID="Bob Stewart EXOCHAIN Release Signing <bob@bobstewart.com>"
RELEASE_SIGNING_FINGERPRINT="$(gpg --with-colons --fingerprint "$RELEASE_SIGNING_UID" | awk -F: '/^fpr:/ { print $10; exit }')"
gpg --armor --export "$RELEASE_SIGNING_FINGERPRINT" > exochain-release-signing-public.asc
git config --global user.signingkey "$RELEASE_SIGNING_FINGERPRINT"
git config --global tag.gpgSign true
```

Configure the repository variables used by `.github/workflows/release.yml`:

```bash
gh variable set EXOCHAIN_RELEASE_SIGNING_FINGERPRINT --repo exochain/exochain --body "$RELEASE_SIGNING_FINGERPRINT"
gh variable set EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC --repo exochain/exochain < exochain-release-signing-public.asc
gh gpg-key add exochain-release-signing-public.asc --title "EXOCHAIN Release Signing"
```

Create and verify the signed release tag only after the key is configured:

```bash
git fetch origin main --tags
git tag -s v0.2.3 "$(git rev-parse origin/main)" -m "EXOCHAIN v0.2.3"
git tag -v v0.2.3
git push origin v0.2.3
```

### Dry Run

Trigger via the GitHub Actions UI with `dry_run=true`. A dry run still traverses
the `release` environment, runs the full CI workflow, builds both native release
archives from the dispatched commit, and builds and dry-packs the WASM and LYNK
npm packages. It skips the signed-tag requirement, SBOM/SLSA job, crates.io and
npm publication, and does not create a GitHub Release.

```bash
# Quick local validation (does not replicate the full release pipeline):
cargo build --workspace --release
cargo test --workspace
```

### DualControl Configuration

The workflow source proves that publication jobs `need` both `release` and
`release-second` environment gates. It does not prove the repository's current
environment protection rules. Inspect those rules before every live release:

```bash
gh api repos/exochain/exochain/environments/release \
  --jq '{protection_rules, can_admins_bypass}'
gh api repos/exochain/exochain/environments/release-second \
  --jq '{protection_rules, can_admins_bypass}'
```

GitHub environment required reviewers are a one-of gate: Only one configured
required reviewer needs to approve a waiting job. Listing two council reviewers
on a single environment therefore does not establish two-person approval.
`prevent_self_review` and `can_admins_bypass=false` strengthen a single
approval but still do not create a second independent approval. Two
environments with distinct reviewers do.

A live release must not be dispatched until two distinct approvals are enforced
by independently protected workflow gates or an equivalent custom deployment
protection rule, with current repository-setting evidence retained alongside the
release record. Dry runs still traverse the `release` environment but perform no
publication or GitHub Release write.

## Rollback (Yank) Procedure

Once a version is published to crates.io it cannot be deleted, but it can be yanked
to prevent new projects from depending on it.

**When to yank:** defective API, security vulnerability, broken build, or council
resolution requiring retraction.

```bash
# Yank a specific crate version (repeats for each affected crate)
cargo yank --version 0.2.3 exochain-core

# Restore a yank if issued in error
cargo yank --version 0.2.3 exochain-core --undo
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
