# Quality Gates

These gates are enforced by the `DEVOPS_RELEASE_AGENT` via the CI pipeline at `.github/workflows/ci.yml`.

Coverage target: **90%** per CR-001 Section 8.8.

## Pull Request Gates (20 Numbered Gates + Aggregator — Must Pass to Merge)

1. **Build**: `cargo build --workspace --release` succeeds.
2. **Test**: `cargo test --workspace` and `cargo test --workspace --release` pass.
3. **Coverage**: `cargo tarpaulin` reports **>= 90% line coverage** for the configured workspace scope.
4. **Clippy**: `cargo clippy --workspace --all-targets -- -D warnings` passes.
5. **Format**: `cargo +nightly fmt --all -- --check` passes.
6. **Audit**: `cargo audit` passes.
7. **Deny**: `cargo deny check` passes.
8. **Documentation**: `cargo doc --workspace --no-deps` passes.
9. **Repo Hygiene**: generated artifacts, tracked secrets, license drift, GAP stubs, and repo-truth drift are rejected.
10. **SBOM Dry-Run**: CycloneDX generation path is validated.
11. **Unused Dependencies**: `cargo machete` passes.
12. **Gateway Integration**: gateway route tests pass when relevant.
13. **DB Integration**: production-db integration tests and migrations pass.
14. **Consensus Integration**: multi-node consensus test passes.
15. **State Sync & Join**: state sync/join test passes.
16. **Cross-Platform Build**: Linux x86_64, Linux aarch64, and macOS aarch64 build targets pass.
17. **0dentity Coverage**: 0dentity module coverage meets the configured threshold.
20. **WASM Build**: wasm-pack build passes.
21. **Bridge Verification**: JS bridge verification passes.
22. **WASM/JS Export Sync**: Rust exports and JS bridge coverage remain synchronized.

### CI Pipeline Reference

All gates are automated in `.github/workflows/ci.yml`. PRs cannot merge until all numbered gates and the "All Constitutional Gates" aggregator pass.

## Release Gates (Must Pass to Ship)

1. **Cross-Implementation Test**: `tools/cross-impl-test` passes (Rust vs JS hash consistency).
2. **Benchmarks**: `cargo bench` shows no regression > 10% vs baseline.
3. **Fuzzing Smoke**: Fuzz targets run for 5 mins with 0 crashes.
4. **Changelog**: `CHANGELOG.md` updated with conventional commits.
5. **Post-Quantum Signature Validation**: All three `Signature` enum variants (Ed25519, PostQuantum, Hybrid) pass roundtrip sign/verify tests.
6. **Constitutional Invariant Verification**: AEGIS/SYBIL invariants verified against current traceability and threat matrices; planned or partial rows remain release-blocking for claims of constitutional completeness.

### CR-001 Section 8.8 Release-Blocking Gates

The following gates are release-blocking per the draft CR-001 release-blocking criteria:

* 90% minimum line coverage across all crates
* Zero test failures across the full workspace
* All current threat model mitigations verified
* All traceability matrix requirements mapped and tested, with no planned or partial rows for release-complete claims
* Constitutional invariant proofs pass verification
* Post-quantum signature scheme validation complete

## Invariant Enforcement

* **No PII**: Static analysis / grep check for "password", "secret", "pii" keys in log statements.
* **No Floats**: `#[deny(clippy::float_arithmetic)]` enforced **workspace-wide** in the root `Cargo.toml`. No `f32` / `f64` usage permitted anywhere. All arithmetic uses fixed-point or integer types.
* **No Unsafe**: `#![forbid(unsafe_code)]` in critical crates.
* **No Panics**: `unwrap()`, `expect()`, and `panic!()` forbidden in production code.
* **Post-Quantum Ready**: `Signature` enum (Ed25519/PostQuantum/Hybrid) validated in CI; all variants must pass verification.
