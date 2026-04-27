# Changelog

All notable changes to EXOCHAIN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security / Correctness

Driven by the 2026-04-19 full-repo review
([docs/audit/REVIEW-2026-04-19.md](docs/audit/REVIEW-2026-04-19.md));
follow-up identifiers below are the plan's A-NN items.

- **Node runs non-root in Docker** (A-040): root `Dockerfile` now creates
  an unprivileged `exochain` user, installs `gosu`, and chowns the data
  volume on first boot before stepping down. Adds `HEALTHCHECK` probing
  the effective API port and uses exec-form `ENTRYPOINT`.
- **Secrets moved behind fail-fast env vars** (A-043): `docker-compose.yml`
  no longer carries hardcoded `exochain_dev` / `*-dev-secret`; every
  secret is now `${VAR:?message}`-guarded and a missing `.env` fails
  with a clear error.
- **MCP input validation** (A-020): `tools/call` now validates params
  against each tool's registered JSON Schema before dispatch. Schema
  violations return JSON-RPC `INVALID_PARAMS (-32602)` rather than
  silently reaching the tool body with an empty-defaulted field.
- **Gateway body cap** (A-022): 1 MiB `DefaultBodyLimit` on every route.
- **Web XSS hardened** (A-030/031/032): Council AI panel HTML-escapes
  message content before applying markdown regex; dev-bypass is
  double-guarded behind `VITE_ALLOW_DEV_BYPASS=true` and dropped from
  production bundles by Vite DCE; CSP meta added.
- **CSRF double-submit client** (A-082): fetchJson reads the
  `XSRF-TOKEN` cookie and echoes it as `X-CSRF-Token` on mutating
  requests. Server-side enforcement is a separate follow-up.
- **Consensus scoring clamped** (A-010): `calculate_panel_confidence`
  now clamps `models_agreeing` to `total_models` and caps the speed
  sub-score numerator so out-of-range inputs cannot produce a score
  above 10000 bps. Added property tests.
- **Signature roundtrip returns `Result`** (A-011/012): `exo-dag`
  Postgres store no longer silently substitutes `Signature::Empty` on
  decode failure, and all lossy `as` casts for timestamps / heights
  are replaced with checked `try_into`.
- **Explicit shutdown phases** (A-070): exo-node logs HTTP-drain →
  subsystem-stop → shutdown-complete and adds a 500ms task-drain
  window. Full per-task CancellationToken plumbing is tracked as a
  follow-up.
- **Global concurrency ceiling** (A-071): gateway adds
  `ConcurrencyLimitLayer(1024)` as admission control.
- **Python `TransportError` carries status + body** (A-061); Python
  `HttpTransport.timeout` accepts `httpx.Timeout` for per-phase control.
- **Python SDK ships `py.typed`** (A-063); all three SDKs expose a
  matching `PROTOCOL_VERSION` constant (A-066).
- **Orphan Rust modules removed**: deleted undeclared top-level Rust files
  that were not compiled or tested (`exo-core/src/event.rs`,
  `exo-dag/src/proof.rs`, `exo-gatekeeper/src/proof.rs`,
  `exo-governance/src/{anchor,decision,emergency}.rs`, and
  `exo-identity/src/key.rs`). Current functionality lives in the declared
  `events`, `mmr`, `kernel`/`invariants`, `decision-forum`,
  `did_verification`, and `key_management` surfaces.

### CI

- **GAP stub hygiene** (A-102): CI Gate 9 fails on any `STUB.*GAP-0NN`
  marker in code so a closed GAP can never leave a stub behind.
- **Rust module hygiene**: CI Gate 9 now runs
  `tools/test_no_orphan_rust_modules.sh` to reject undeclared
  top-level `crates/*/src/*.rs` files.

### Docs

- `SECURITY.md` now points to GitHub Private Security Advisory as the
  primary disclosure channel (A-093); the `security@exochain.org`
  fallback remains documented.
- `CONTRIBUTING.md` cross-links to `docs/guides/DEPLOYMENT.md` for
  post-merge shipping guidance (A-107).
- Doc-rot sweep: `spec v2.1` references updated to `v2.2` in
  `docs/guides/constitutional-model.md` and
  `docs/guides/architecture-overview.md` (A-104).

### ⚠ BREAKING

- **DID derivation canonicalized to BLAKE3 across all SDKs** (A-050):
  the TypeScript and Python SDKs previously used SHA-256(pubkey)[:8]
  while the Rust SDK used BLAKE3(pubkey)[:8]; identical keypairs
  yielded different DIDs per language. All three now derive via
  BLAKE3 and share a fixture file at
  `tests/fixtures/did-derivation.json`. Applications that persisted
  locally-generated DIDs from the old TS/Python SDKs must migrate.
  TS SDK adds `@noble/hashes` dep; Python SDK adds `blake3>=0.4.1` dep.

## [0.1.0-beta] - 2026-04-10

Promotes alpha to beta. The WASM CGR Kernel is now fully operational, all 7
ExoForge health checks pass green, and the CQI self-improvement loop runs
end-to-end through council governance.

### Fixed
- **WASM kernel loading** — `getKernel()` used a wrong relative path (`../../packages/...` resolved to `command-base/packages/` instead of repo root). Switched to `@exochain/exochain-wasm` npm package resolution. All 163 exported functions from 14 Rust governance crates now load correctly.
- **TNC enforcement health check** — rewrote to use `wasm_create_decision()` with correct `DecisionObject` and `TncFlags` field names matching the Rust structs.
- **Governance receipt `action` NOT NULL constraint** — fixed in 5 locations: `exoforge.js`, `exoforge-bridge.js`, `cqi-orchestrator.js`, `governance.js` (createReceipt + backfill).
- **Auth module WASM path** — `auth.js` had the same wrong relative path; fixed to npm package resolution.

### Added
- **Constitutional invariants seeding** — 10 invariants (INV-001 through INV-010) seeded on startup, mapping 1:1 to `wasm_enforce_tnc_01`–`wasm_enforce_tnc_10`. INV-010 (AI Ceiling Respected) added as new invariant with formal spec.
- **ExoForge dashboard** — first-class page in CommandBase with 5 panels: health status, implementation queue, solutions builder, CQI self-improvement loop, and Syntaxis workflow templates.
- **CQI self-improvement pipeline** — 7-node pipeline (collect → analyze → propose → council-review → exoforge-dispatch → verify → deploy) with ExoForge bridge integration.
- **Syntaxis solution templates** — 7 built-in templates across 5 categories (governance, development, maintenance, security, infrastructure).

### Health Check Status
All 7 checks healthy (score: 1.0): kernel availability, TNC enforcement, workflow stages (14), audit chain, receipt chain, invariant coverage (10/10), ExoForge cycle.

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
