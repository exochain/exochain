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
version = "0.2.6"
```

This repository state is the intended, unpublished `0.2.6` security-remediation
release candidate. The latest published release remains `v0.2.4`. Read-only
provider checks at `2026-08-29T03:44:56Z` found no `v0.2.5` remote tag or
GitHub Release, HTTP 404 for `0.2.5` across all 32 publishable Rust packages,
and npm E404 for both versioned npm packages; `0.2.4` provider controls were
reachable. Workspace version alignment is not evidence of a tag, GitHub
Release, registry publication, deployment, or live runtime activation.

## Release Process

See `.github/workflows/release.yml` for the automated release workflow:

1. The full CI workflow, including the numbered constitutional gates and required aggregator, must pass.
2. Every dispatch traverses two independent GitHub environments (`release` and `release-second`) with distinct required reviewers. One environment is one-of; two environments are two-of. Repository settings, not workflow source, determine the reviewer lists.
3. Every release checkout is the validated workflow-dispatch commit and must initially be clean, including untracked files. Immediately before each artifact or publication side effect, the workflow rebinds every trusted value at step scope, runs a privileged profile-free Bash that cannot import functions, neutralizes `BASH_ENV`, rejects inherited shell-function definitions, scrubs inherited Git repository/index/object/configuration controls, loads the guard and both child verifiers from the immutable dispatch commit with system Git and replacement objects disabled, anchors source inspection to `GITHUB_WORKSPACE`, disables fsmonitor and untracked-cache shortcuts, and rechecks immutable `HEAD`; once expected build outputs exist, it still rejects staged or tracked-source drift and rejects index flags that could hide it. A non-dry-run release additionally requires an existing annotated, cryptographically verified signed `v<version>` tag whose peeled commit equals the workflow-dispatch commit and checked-out `HEAD`. The isolated signing keyring must contain exactly the configured primary key and its subkeys, and the machine-readable signature result must chain the actual signer to that primary. The signed-tag gate records the immutable tag-object ID and peeled commit; every live side-effect boundary queries the exact tag-object and peeled-commit refs at the validated GitHub repository endpoint from a fresh directory outside the checkout with an empty inherited environment and disabled global/system Git configuration, so a checkout remote or local URL rewrite cannot substitute another repository. Both immutable values are compared again, including before each retrying crate publication and the final GitHub Release creation step.
4. Native artifacts are built for `x86_64-linux-gnu` and `aarch64-linux-gnu`.
5. Non-dry-run releases generate CycloneDX workspace SBOMs and GitHub SLSA build attestations via OIDC/Sigstore.
6. Non-dry-run releases publish crates in dependency order and publish the versioned npm packages after their dry-pack gates pass.
7. Non-dry-run release artifacts and SBOMs are attached to the existing signed `v<version>` tag in a published GitHub Release.

### Release Signing Key Setup

Live releases require an approved OpenPGP signing key controlled by the release
maintainer. The public key and full fingerprint must be configured as repository
variables so the release workflow can import the key on the GitHub runner before
verification. The exported bundle must contain exactly that configured primary
key and its legitimate subkeys; additional primary keys are rejected. A tag may
be signed by the configured primary or by one of its signing subkeys, but the
reported signer primary fingerprint must equal the configured fingerprint.

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
git tag -s v0.2.6 "$(git rev-parse origin/main)" -m "EXOCHAIN v0.2.6"
git tag -v v0.2.6
git push origin v0.2.6
```

### Dry Run

Trigger via the GitHub Actions UI with `dry_run=true`. A dry run still traverses
the `release` environment, runs the full CI workflow, builds both native release
archives from the dispatched commit, and builds and dry-packs the WASM and LYNK
npm packages. It skips the signed-tag requirement, SBOM/SLSA job, crates.io and
npm publication, and does not create a GitHub Release.

```bash
# Quick local validation (does not replicate the full release pipeline):
cargo build --workspace --release --locked
cargo test --workspace --locked
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
