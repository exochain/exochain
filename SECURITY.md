# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| `0.1.0` | Current release — supported |
| `main` branch | Development — may contain unreleased changes |

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
- Cryptographic implementations (BLAKE3, Ed25519, Shamir, SNARK/STARK stubs)

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
- **Release workflow** produces provenance attestation (`provenance.json`) with SHA-256 hashes for every release artifact
- **GPG-signed tags** — every release tag is cryptographically signed; verify with `git tag -v v<version>`

### Release Signing Key Policy

All release tags are signed with a GPG key held by an EXOCHAIN maintainer.

| Field | Value |
|-------|-------|
| Key type | Ed25519 or RSA-4096 |
| Key storage | Offline hardware token or secrets manager; never on CI runners |
| Rotation cadence | Annually or on suspected compromise |
| Compromise response | Immediately rotate key, yank affected releases, open `exochain:council-review` issue |

To verify a release tag:

```bash
# Import the maintainer public key (published at https://exochain.org/pgp-key.asc)
gpg --keyserver keys.openpgp.org --recv-keys <KEY_FINGERPRINT>

# Verify the tag
git tag -v v0.1.0
```

The key fingerprint for the current signing key will be published in the GitHub
release notes and on the project website. If a tag cannot be verified, **do not use
the release** — contact security@exochain.org.
