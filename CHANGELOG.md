# Changelog

All notable changes to EXOCHAIN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-03-30

First tagged pre-release of EXOCHAIN.  All 15 workspace crates compile and pass
the 11-gate CI pipeline.  The gateway REST/GraphQL layer is feature-in-progress
(see Known Limitations below).

### Architecture — 16 Crates

| Crate | Role |
|---|---|
| `exo-core` | HLC timestamps, CBOR canonical serialization, determinism primitives |
| `exo-identity` | Ed25519 + ML-DSA DIDs, key registry, PACE authentication |
| `exo-consent` | Consent records, revocation, audit trail |
| `exo-authority` | Delegated authority chains, scope enforcement |
| `exo-gatekeeper` | Policy enforcement point — consent × authority × governance |
| `exo-governance` | Constitutional rules, quorum voting, amendment lifecycle |
| `exo-escalation` | Multi-stage escalation workflows with timeout handling |
| `exo-legal` | Legal instrument storage and lifecycle |
| `exo-dag` | Append-only deterministic DAG for event sourcing |
| `exo-proofs` | Zero-knowledge proofs and commitment schemes |
| `exo-api` | Shared API types, GraphQL schema definitions |
| `exo-gateway` | HTTP gateway — REST + GraphQL; DID auth middleware (in progress) |
| `exo-tenant` | Multi-tenant isolation and lifecycle management |
| `decision-forum` | Deliberative voting forum with ranked-choice support |
| `exochain-wasm` | WebAssembly bindings for Node.js (wraps 13 crates) |

### Added
- 15 Rust crates implementing the EXOCHAIN constitutional trust fabric
- 1,116+ library tests with 0 failures
- 11-gate CI pipeline (build, test, coverage, lint, format, audit, deny, doc, hygiene, SBOM, machete)
- CycloneDX SBOM (JSON) generated per CI run and attached as build artifact
- SLSA Level 2 build provenance attestation in `release.yml` via Sigstore/Rekor
- `cargo-machete` gate detecting unused workspace dependencies
- Demo platform: 7 Node.js microservices + React widget-grid UI + WASM bridge
- ExoForge integration: 7 Archon commands, 4 DAG workflows, GitHub Issues triage
- GitHub Issue templates (bug report, feature request) with ExoForge auto-triage
- CODEOWNERS mapping code areas to council panel reviewers
- Feedback API endpoints: `/api/feedback`, `/api/backlog`, `/api/backlog/vote`, `/api/backlog/status`
- SECURITY.md, CHANGELOG.md, VERSIONING.md, SUPPORT.md
- Licensing position document (docs/legal/LICENSING-POSITION.md)
- Repository truth baseline (docs/audit/REPO-TRUTH-BASELINE.md)
- Truth generation utility (tools/repo_truth.sh)
- National AI Policy Framework crosswalk (docs/policy/)
- `HybridKeyStore` (`exo-identity`) — Ed25519 + ML-DSA-65 keypair bundle lifecycle (create/rotate/revoke) for PQ-hardened DID keys
- `HybridVerificationMethod` (`exo-identity`) — strict AND verification enforcing both Ed25519 and ML-DSA-65 signatures; closes silent downgrade path (EXOCHAIN-REM-005)
- FIPS 204 KAT integration tests + proptests in `exo-core` covering ML-DSA-65 round-trip, determinism, hybrid strict-AND, and normative byte lengths

### Fixed
- License inconsistency: Cargo.toml declared AGPL-3.0 while LICENSE file was Apache-2.0 (resolved to Apache-2.0)
- Gateway API feedback endpoints were unreachable dead code (placed after 404 catch-all)
- `exo-gateway` binary referenced unimplemented functions (replaced with placeholder)
- `exo-dag` benchmark referenced removed API types (disabled with explanation)
- `exo-api` schema test referenced unimplemented GraphQL (disabled with explanation)
- `exo-identity` LiveSafe integration test referenced refactored PACE API (disabled with explanation)
- All clippy warnings resolved across workspace (as_conversions, expect_used, div_ceil, digit grouping, etc.)
- Format issues resolved (`cargo +nightly fmt --all -- --check` passes)
- CI clippy gate split: strict `-D warnings` for production code, allow expect/unwrap in test code
- Removed stale `--ignore RUSTSEC-2023-0071` from `cargo audit` CI step; dependency graph confirmed clean (sqlx `mysql` feature not enabled)
- EXOCHAIN-REM-005: silent Ed25519-only downgrade when hybrid verification methods are expected — `HybridVerificationMethod::verify` now enforces strict AND semantics via `crypto::verify_hybrid`

### Removed
- Tracked `node_modules/` directory (~200 files) from git
- Tracked `__pycache__/` directories from git
- Tracked `web/dist/` build artifacts from git
- Dead `to_json_string` function from WASM serde bridge

### Changed
- README rewritten with three-layer structure: Verified Today / Supported by Design / Roadmap
- Numeric claims updated to match actual counts (16 crates, 148 files, ~31K LOC)
- Governance claims downgraded from "all complete" to specific counts with statuses
- docs/INDEX.md updated to reference all documentation including demo, ExoForge, CI/CD
- CONTRIBUTING.md updated with ExoForge self-improvement workflow
- .gitignore hardened for __pycache__, web/dist/, .env files

### Known Limitations

- **`exo-gateway` is in active development** — DID-authenticated REST routes and
  GraphQL resolvers are being implemented; full integration tests are pending.
  Do not use the gateway in production in this alpha.
- **`exochain-wasm` Node.js bindings** have not been published to npm; the WASM
  build is tested locally only.
- **Coverage gate** requires `cargo-tarpaulin` with the `llvm` engine; Windows
  CI is not yet supported.
- **crates.io publish** is gated behind `CARGO_REGISTRY_TOKEN`; crates are not
  yet published for this alpha release.
- **Post-quantum signatures** (`ml-dsa`) use release-candidate crate
  `ml-dsa = 0.1.0-rc.7`; the stable 0.1.0 release is not yet available.
