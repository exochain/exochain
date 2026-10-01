# CI Reproducibility Repair Design

Date: 2026-10-01. Related release issue: #844. This repair follows PR846's normal integration as `36a133f48516358361b6e453ef8f9e3157aa5257`, whose tree exactly matches reviewed candidate `7832bb47139e6f6feecc2dfec219a071b80da989`. Both genuine final-head human approvals preceded that merge.

## Observed failures and selected contract

Integrated CI run 36866376154 attempt 1 exposed two distinct tooling failures. Gate 4 selected Rust 1.99.0 through floating stable; both successful candidate Clippy jobs had actually used 1.98.1. The unchanged async-trait 0.1.89 macro emits six message-less must_use attributes that the newer validator rejects. This repair selects the previously validated compiler release explicitly. It does not claim compatibility with Rust 1.99.0 or change the declared MSRV 1.85.

Gate 7 failed during construction of the pinned third-party Docker action, before checkout or policy execution. Three runner-managed attempts piped a public release-archive response into tar, which rejected it as invalid gzip. The historical HTTP status, response body, and curl status were not recorded; the underlying provider cause remains unknown. No blind retry is justified by that evidence.

The integrated run finished failure at 13:17:17 UTC: its complete 28-job inventory contains 11 successes, four failures and 13 skipped jobs. The other failures are the release build and Windows custody job: both installed Rust1.99.0 and warning denial rejected newly deprecated Atomic::fetch_update calls in exo-node main.rs and its crosschecked_anchor_persistence integration test. The Windows runtime custody assertions were not reached; this is not evidence they failed. The selected18-consumer pin includes both jobs; production code and warning denial stay unchanged.

Use the existing canonical locked Cargo installation path instead of this opaque Docker bootstrap, retaining cargo-deny 0.19.2. The runtime deliberately changes from the action's Rust 1.85.0 Alpine/musl container to the job's pinned Rust 1.98.1 Ubuntu/GNU host. Fresh actual policy validation must establish the outcome; equal command strings do not establish runtime equivalence.

## Owned changes and boundaries

All changed source paths are EXOCHAIN core CI, tooling, or project validation documentation. No adjacent surface or core runtime adapter changes are included. Raw job logs and diagnosis reports are imported evidence retained outside source; upstream action and registry source are third-party/vendor and remain read-only.

- `.github/workflows/ci.yml`: pin precisely the 18 current floating stable toolchain inputs to 1.98.1; add compiler and Clippy version reporting; replace only the Deny bootstrap/execution boundary.
- `tools/test_github_actions_pinned.sh`: extend the existing parsed-YAML contract and mutation tests for the exact CI toolchain inventory and unchanged required lint execution. Reuse its Psych parser, duplicate-key rejection and existing formatter checks.
- `tools/test_ci_supply_chain_hardening.sh`: extend the existing supply-chain guard with the parsed Deny job contract and controlled shell failure tests of the actual workflow run strings. No parallel installer.
- `README.md`, `CONTRIBUTING.md`, `AGENTS.md`: distinguish exact CI reproduction from MSRV and preserve dated formatting/publication instructions.
- This design and its implementation plan record the bounded repair and evidence limits.

No crate, package, Cargo manifest/lock, deny.toml policy, historical recovery JSON, release.yml, retirement workflow, artifact, tag, permissions, or protected-environment rule changes. No global rust-toolchain file or default-toolchain update.

## Validation contract

The 18 CI jobs are build, test, coverage, lint, deny, doc, machete, integration-tests, integration-tests-db, consensus-integration, state-sync-integration, cross-platform, zerodentity-coverage, root-genesis-coverage, root-genesis-portal-coverage, build-wasm, unaudited-feature-matrix, and private-file-windows. Each keeps its current components, targets, commands, and relationships except the expressly described Deny change and version-reporting addition. Formatter remains nightly-2026-09-21; sealed SBOM/publication protocol parity remains 1.97.1.

Clippy remains `cargo clippy --workspace --all-targets -- -D warnings`, with global RUSTFLAGS warning denial. Record `rustc --version --verbose` and `cargo clippy --version` immediately before the check. No allow attribute, dependency upgrade, crate exclusion, skip, or error suppression.

Deny runs on ubuntu-latest with a 30-minute job timeout. Installation uses `bash tools/ci_cargo_retry.sh cargo install cargo-deny --version 0.19.2 --locked` with `CI_CARGO_RETRY_ATTEMPTS: "1"`. Require and print exact output `cargo-deny 0.19.2` from `cargo deny --version`; mismatch fails before checking. Set `CARGO_NET_GIT_FETCH_WITH_CLI: "false"` for the check, retaining global color/network policy. Execute exactly `cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check` once, with all four default policy categories, followed by the existing dependency pin guard. Keep deny in all-gates.needs and both steps unconditional/fail-closed. The policy command is never wrapped in retry or fallback.

Regression tests must first reject current source, then pass the repaired actual source. Parsed contracts must reject missing/duplicate jobs or installations, new floating/wrong/expression toolchains, changed formatter/SBOM pins, lint suppression or narrowed arguments, and disconnected unconditional hygiene/aggregator checks. Deny mutations must reject a different version, missing lock/all-features/manifest/category checks, installer retries, missing version guard, skips, continue-on-error, swallowed exits, reordered/missing pin guard, or fallback checker. Behavioral fixtures execute actual parsed run strings with controlled executables: failed installation prevents check execution, wrong version prevents execution, checker failure propagates once, and successful execution preserves the exact argument vector. Fixtures are not real Cargo acceptance.

Main alone runs actual Cargo/toolchain operations with CARGO_BUILD_JOBS=2, CARGO_INCREMENTAL=0, all DEV/TEST/RELEASE debug settings 0 and at least 4 GiB free. Install the named 1.98.1 toolchain without changing defaults. Actual full final-candidate gates use a new evidence root and source binding; completed historical runners and provider helpers are never restarted. Preserve known ignored tests, historical replay gap, external-platform limits and warnings honestly. Fresh hosted exact-head CI must verify the new toolchain and Deny behavior on relevant platforms.

## Authority, integration and release

Bob's standing explicit authority covers necessary fixes, implementation, separate technical review and legitimate release continuation; no broad approval re-ask. This does not substitute for two genuine distinct nonauthor final-head approvals, normal signed integration, integrated CI or protected DRY/LIVE decisions. Preserve failed run 36866376154 as failure and all earlier green evidence as historical. No release operation until the repaired integrated controller satisfies actual prerequisites. Exact preserved bytes, current custody/nonexpiry, direct current receipts, all-provider/35-asset acceptance and separate post-release retirement remain unchanged.
