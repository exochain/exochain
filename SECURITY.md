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

# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| `main` branch | Supported for vulnerability intake and coordinated fixes |
| `v0.1.0-alpha`, `v0.1.0-beta` | Unsigned pre-release git tags; not formal supported releases |

## Reporting a Vulnerability

If you discover a security vulnerability in EXOCHAIN, please report it
responsibly via **GitHub Private Security Advisory**. This is the
preferred channel:

- Go to https://github.com/exochain/exochain/security/advisories/new
- Or, from the repository: **Security** tab → **Advisories** → **New draft advisory**

GitHub Security Advisories give you a private workspace that is scoped to
the repository, let the maintainers comment in-thread, and coordinate a
release + CVE assignment when the fix ships. They do not require an email
server on the reporter's end and they are the fastest path to a patched
release.

If the GitHub UI is not available to you, email `security@exochain.org`
as a fallback. Email is monitored on a best-effort basis; the Advisory
channel is the primary mechanism.

**Do not open a public GitHub issue for security vulnerabilities.** A
public issue starts the clock on disclosure without letting the
maintainers coordinate a release.

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected crate(s) and code location
- Potential impact assessment
- Any suggested fix

### Canonical origin signals

EXOCHAIN.AI is the canonical public identity signal for EXOCHAIN movement and
trust narrative. Treat visually similar names, domains, packages, prompts, or
emails as security-relevant evidence until provenance is verified. Repository
authority still comes from the canonical source tree, signed commits, reviewed
pull requests, release provenance, and GitHub Security Advisories.

See [Canonical Origin Signals](docs/policy/CANONICAL-ORIGIN-SIGNALS.md).

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix or Mitigation**: Depends on severity; critical issues targeted within 7 days

### Scope

The following are in scope:
- All Rust crates in `crates/`
- WASM bindings (`exochain-wasm`)
- Demo services in `demo/services/`
- CI/CD configurations that could affect supply chain integrity
- Cryptographic implementations (BLAKE3, Ed25519, Shamir, SNARK/STARK proof modules)

The following are out of scope:
- The demo web UI (`demo/web/`) — this is a demonstration frontend, not production code
- Third-party dependencies (report to their maintainers; we will update if patched)

## Security Measures

### Build-Time

- **No floating-point arithmetic** — denied workspace-wide (`clippy::float_arithmetic`)
- **No unsafe code** — denied workspace-wide (`unsafe_code = "deny"`)
- **No OpenSSL** — banned via `cargo-deny`; pure-Rust cryptography only
- **Dependency audit** — `cargo audit` in CI (Gate 6)
- **License compliance** — `cargo deny check` in CI (Gate 7)
- **Pure-Rust crypto** — ed25519-dalek, blake3, chacha20poly1305

### Runtime

- **Constitutional invariant enforcement** — 8 invariants checked at every BCTS state transition
- **Trust-critical non-negotiable controls** — 10 TNCs that cannot be bypassed
- **Audit trail** — all governance actions are recorded with HLC timestamps
- **Consent gating** — data access requires explicit, revocable consent

### Supply Chain

- **Source-only dependencies** from crates.io (no git dependencies allowed)
- **`deny.toml`** enforces allowed licenses and bans problematic crates
- **Release workflow** produces CycloneDX SBOM artifacts and GitHub SLSA build attestations for release archives
- **Release tag policy** — non-dry-run releases must use an existing signed `v<version>` tag before artifacts can be published

### Release Signing Key Policy

Formal release tags must be signed with a GPG key held by an EXOCHAIN maintainer.
The current repository contains unsigned pre-release tags (`v0.1.0-alpha` and
`v0.1.0-beta`) and no `v0.1.0` formal release tag.

| Field | Value |
|-------|-------|
| Key type | Ed25519 or RSA-4096 |
| Key storage | Offline hardware token or secrets manager; never on CI runners |
| Rotation cadence | Annually or on suspected compromise |
| Compromise response | Immediately rotate key, yank affected releases, open `exochain:council-review` issue |

To verify a formal release tag and its supply-chain attestation:

```bash
# Import the maintainer public key (published at https://exochain.org/pgp-key.asc)
gpg --keyserver keys.openpgp.org --recv-keys <KEY_FINGERPRINT>

# Verify the tag
git tag -v v<version>

# Verify a release archive attestation
gh attestation verify exochain-<version>-<target>.tar.gz --owner exochain
```

The key fingerprint for the current signing key will be published in the GitHub
release notes and on the project website. If a formal release tag or attestation
cannot be verified, **do not use the release** — contact security@exochain.org.
