# CI Reproducibility Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Restore reproducible, fail-closed validation of the integrated preserved-byte recovery controller.

**Architecture:** Keep the canonical CI job graph and checks. Pin the previously validated Rust release and reuse the existing exact-version locked Cargo installer for Deny; extend existing guards instead of introducing an installer or parser framework.

**Tech Stack:** GitHub Actions YAML, Bash, Ruby/Psych, Rust 1.98.1 and cargo-deny 0.19.2.

**Spec:** governance/releases/v0.2.7/CI-REPRODUCIBILITY-DESIGN.md

## Global Constraints

- Use only the existing sole worktree/local branch; preserve the original dirty checkout. Main owns Git/index/signing/Cargo/provider actions; no worker Cargo or subagents.
- Pin exactly the 18 named CI stable consumers to 1.98.1; formatter remains nightly-2026-09-21 and sealed SBOM/publication parity remains 1.97.1. No default-toolchain change.
- Preserve full lint command and warning denial. Deny uses exact 0.19.2 --locked, one helper installation attempt, exact version check, unchanged all-feature/root-manifest/four-category command, no policy retry, and existing dependency pin/aggregator gates.
- No crates/packages/manifests/locks/deny.toml/four historical JSON/release.yml/retirement workflow/protection changes. No product rebuild/repack/republish, old tag moves or evidence deletion.
- Actual Cargo is main-only with CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_RELEASE_DEBUG=0 and 4 GiB free.
- Technical/fixture/local evidence never substitutes for exact-head human approvals, hosted/integrated CI, protected DRY/LIVE/current receipts or final release acceptance.

## Review Focus

1. Comment-only or deleted/missing job configurations cannot satisfy guards: actual parsed job inventory and duplicate/missing/wrong-pin mutations in Task 1.
2. Install/version failure cannot reach policy execution: actual workflow shell strings with failing controlled executables in Task 1.
3. Policy failure cannot be retried or swallowed: exact argv/call-count/nonzero assertions in Task 1.
4. Validation pin must not change publication or MSRV: immutable-input diff checks and documentation scope in Tasks 1 and 2.
5. A green local fixture must not be labeled hosted or all-platform acceptance: terminal evidence and honest evidence boundaries in Task 2.

### Task 1: Repair and enforce canonical CI reproducibility

**Files:** Modify only `.github/workflows/ci.yml`, `tools/test_github_actions_pinned.sh`, `tools/test_ci_supply_chain_hardening.sh`, `README.md`, `CONTRIBUTING.md`, `AGENTS.md`. Main owns this design/plan and ledger; worker never edits those. Read the Spec and actual existing files before changes. All paths classify as EXOCHAIN core CI/tooling/documentation; fixture outputs are imported evidence retained in unique external temporary directories, with their paths and command outcomes recorded in the ignored task workspace.

**Interfaces:** Consume existing Psych helpers in action-pin guard, existing `tools/ci_cargo_retry.sh` and the existing CI hygiene and all-gates boundaries. Produce extended canonical guards with shell exit0 for valid actual source and nonzero for invalid source; no new production entrypoint or dependency.

- [x] Step 1: Extend existing guard coverage before workflow edits. Require the exact 18-job 1.98.1 inventory: build, test, coverage, lint, deny, doc, machete, integration-tests, integration-tests-db, consensus-integration, state-sync-integration, cross-platform, zerodentity-coverage, root-genesis-coverage, root-genesis-portal-coverage, build-wasm, unaudited-feature-matrix, private-file-windows. Preserve components/targets. Reject malformed/duplicate/missing job/installations, floating/wrong/expression pin and an extra floating consumer. Retain formatter nightly-2026-09-21 and sbom 1.97.1 guards. Verify unchanged all-workspace/all-targets lint command/global warning denial and unconditional hygiene/aggregator reachability; exercise suppression/skip/narrowing/deletion mutations.
- [x] Step 2: Add parsed Deny contract and actual shell-boundary fixture tests in the existing supply-chain guard. Positive job: ubuntu-latest, timeout-minutes30, existing checkout plus 1.98.1 toolchain, installation command `bash tools/ci_cargo_retry.sh cargo install cargo-deny --version 0.19.2 --locked` with CI_CARGO_RETRY_ATTEMPTS "1"; version step captures/prints `cargo deny --version` and requires exact `cargo-deny 0.19.2`; policy step sets CARGO_NET_GIT_FETCH_WITH_CLI "false" and runs exactly `cargo deny --log-level warn --manifest-path ./Cargo.toml --all-features check`; existing security-critical dependency pin guard follows. All steps fail-closed/no if/no continue-on-error; all-gates still needs deny. Mutate every bound version/lock/attempt/argv/order/gate/suppression field. Execute actual parsed run strings with controlled cargo: install exit17 => no policy call; wrong version => no policy call; check exit19 => one call and exit19; success => exact argv once. Do not invoke real Cargo/network in fixtures.
- [x] Step 3: Run `bash tools/test_github_actions_pinned.sh` and `bash tools/test_ci_supply_chain_hardening.sh` against unchanged workflow, saving separate complete expected RED logs/status. The failures must identify the intended current floating/Docker contracts, not syntax or fixture failures.
- [x] Step 4: Change precisely the 18 stable inputs to 1.98.1. Add a lint version step `rustc --version --verbose` then `cargo clippy --version`, preserving the unchanged check. Replace Gate7 action with the exact install/version/check sequence above and a 30-minute job timeout. Preserve all other graph/permission/component/target/command bindings.
- [x] Step 5: Update README, CONTRIBUTING and AGENTS setup/local validation instructions to reproduce CI through named Rust1.98.1 setup and explicit +1.98.1 for corresponding core commands. Keep MSRV1.85 distinct, dated formatter and sealed publication1.97.1 unchanged. Explain pinned validation, not 1.99 compatibility. Do not alter CI/quality requirements.
- [x] Step 6: Run focused GREEN commands once after final edits: `bash tools/test_github_actions_pinned.sh`, `bash tools/test_ci_supply_chain_hardening.sh`, `bash tools/test_security_critical_dependencies_pinned.sh`, `bash tools/test_release_reusable_ci_boundary.sh`, `bash -n` both changed guards, `git diff --check`. Preserve complete logs, all negative fixture counts, errors and warnings. Stop/report before any Cargo-capable or provider operation.
- [ ] Step 7: Self-review the complete six-path diff and write task report with actual RED/GREEN commands/exit codes/raw log paths, classification, exact interfaces and limitations; STOP with source uncommitted. Main performs immutable diff packaging, independent task review, scoped corrections and configured-signed explicit-path commit only after worker stopped.

### Task 2: Verify final source and publish through legitimate review

**Files:** Main updates this plan's checkboxes/ignored progress evidence; external new validation root and immutable review packages. No new production source beyond a separately reviewed finding correction.

**Interfaces:** Consume Task1 reviewed exact files and terminal raw focused evidence. Produce a clean signed exact candidate, full fresh verification record, whole-branch verdict and normal PR head with genuine CI/reviews; no fabricated completion.

- [ ] Step 1: Main adjudicates full task review and every limitation. Inspect immutable-input diff and unchanged tree inputs. Sign exact source/design/plan paths before full validation; verify signature, branch, index, source inventory and at least4GiB free.
- [ ] Step 2: Main installs named Rust1.98.1 with clippy/rustfmt without default change, preserves real compiler/Clippy banners, actually installs cargo-deny0.19.2 --locked with one canonical helper attempt and checks exact version, then executes the exact all-feature policy command. Respect all resource bounds, one current execution and durable raw logs. No old runner rerun. Failure is preserved/diagnosed, never transformed into success.
- [ ] Step 3: Derive full actual current required local command inventory from CI/source and prior reviewed runner; create a separately reviewed new runner/new root binding the final clean signed source and real runtimes. Full core build/debug-release tests/Clippy/format/audit/deny/docs/cross-impl plus all current Python/shell guards execute with terminal raw evidence. Preserve generated outputs safely, named historical replay gap/ignored tests/external-platform limits, all input hashes and no mutation claims. Do not repeat successful unchanged provider helper merely for a CI-only repair; source/scope applicability must be independently checked.
- [ ] Step 4: Independent full raw-log audit and most-capable whole-branch review; main reads/adjudicates both. Fix concrete findings through one consolidated independently reviewed wave, rerunning affected/final required evidence on the actual final candidate. Do not claim readiness until all required work actually completes.
- [ ] Step 5: Normal push to a new checked-unused bob-stewart/ repair branch, create/attach accurate PR with historical failure/current evidence distinction, request Max/Robert once for this genuinely new final head. Follow actual exact-head CI, no rerun green jobs or substitute agent consent. After genuine2non-authorheadapprovals/greenCI, normal integration, exact tree/signature/integratedCI and unchanged protected release path; close neither844nor822 prematurely.
