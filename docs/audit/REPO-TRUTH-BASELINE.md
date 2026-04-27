# EXOCHAIN Repository Truth Baseline

> Superseded numerically by `tools/repo_truth.sh` as updated in Wave E Basalt
> on 2026-04-26. This file is retained as a historical audit baseline, not as
> the current source of repo counts.

Generated: 2026-03-20
Branch: `feat/platform-hardening` @ `bf38f9f`
Method: Manual audit + automated verification

---

## 1. Repository Structure

| Area | Count | Notes |
|------|-------|-------|
| Rust crates | **15** (not 14) | `exochain-wasm` is the 15th, added after README was written |
| Rust source files (`*.rs`) | **148** (not 136) | README claims 136, stale |
| Rust lines of code | **31,094** (not 29,587) | README claims 29,587, stale |
| Library tests (passing) | **1,116** | ✅ Verified via `cargo test --workspace --lib` |
| Test failures | **0** | ✅ Verified |
| Demo services (Node.js) | 7 | gateway-api, identity, consent, governance, decision-forge, provenance, audit |
| Demo React widgets | 23 | In `demo/web/src/App.jsx` |
| TLA+ specs | 5 | AuthorityChain, AuditLogContinuity, ConstitutionalBinding, DecisionLifecycle, QuorumSafety |

## 2. Build Status

| Check | Status | Notes |
|-------|--------|-------|
| `cargo build --workspace --lib` | ✅ PASS | All library crates compile |
| `cargo build --workspace --all-targets` | ❌ FAIL | `exo-gateway` binary has unresolved imports (tokio, dotenvy, missing functions); `exo-dag` bench has stale imports |
| `cargo test --workspace --lib` | ✅ PASS | 1,116 tests, 0 failures |
| `cargo test --workspace --all-features` | ❌ FAIL | Blocked by `exo-gateway` binary compilation |
| `cargo clippy --workspace --all-targets -- -D warnings` | ❌ FAIL | `as_conversions` lint in `exo-core` (hlc.rs, types.rs); `exo-gateway` errors |
| `cargo +nightly fmt --all -- --check` | ❌ FAIL | 1 import order issue in `exochain-wasm/src/serde_bridge.rs` |
| `cargo deny check` | ⚠️ NOT INSTALLED | `cargo-deny` not in local toolchain; cannot verify locally |

## 3. License Declarations — INCONSISTENT

| Source | License Declared |
|--------|-----------------|
| `LICENSE` file | **Apache-2.0** (full Apache 2.0 text) |
| `Cargo.toml` workspace | **AGPL-3.0-or-later** |
| All 15 crate `Cargo.toml` | `license.workspace = true` → **AGPL-3.0-or-later** |
| `deny.toml` | Comments reference "AGPL boundary"; allows AGPL-3.0 |
| `README.md` | "Apache-2.0 — See LICENSE" |
| `CONTRIBUTING.md` | "Uphold the Apache 2.0 License" |

**Verdict**: LICENSE file and public documentation say Apache-2.0. Cargo metadata and deny.toml say AGPL-3.0-or-later. These are fundamentally different licenses with different obligations. **Must be resolved.**

## 4. Public Claims vs Reality

| Claim | Source | Verified | Actual |
|-------|--------|----------|--------|
| "14 crates" | README, INDEX | ❌ | **16 crates** (exochain-wasm + exo-node added) |
| "136 source files" | README | ❌ | **148 source files** |
| "29,587 lines of Rust" | README | ❌ | **31,094 lines** |
| "1,116 tests" | README | ✅ | 1,116 lib tests pass |
| "0 failures" | README | ✅ | 0 failures in lib tests |
| "75/75 requirements implemented" | README | ⚠️ PARTIALLY | 76 🟢, 2 🟡, 2 🔴 in traceability matrix. Not 75/75. Some are partial/planned. |
| "13/13 threats mitigated" | README | ⚠️ PARTIALLY | 15 🟢, 2 🟡, 2 🔴 in threat matrix. Not all fully mitigated. |
| "11 agents, all missions complete" | README | ⚠️ UNVERIFIABLE | Claims in `sub_agents.md` are self-declared, not machine-verifiable |
| "All 3 phases complete" | README | ⚠️ UNVERIFIABLE | Self-declared in refactor plan |
| "90%+ coverage" | CI yml | ⚠️ NOT VERIFIED | tarpaulin not run locally; CI may or may not achieve this |
| "decision-forum: 131 tests" | README | ❓ | Would need to count per-crate |

## 5. Release State

| Item | Status |
|------|--------|
| Published releases | **None** |
| Git tags | **None** |
| CHANGELOG.md | **Missing** |
| SECURITY.md | **Missing** |
| SUPPORT.md | **Missing** |
| VERSIONING.md | **Missing** |
| SBOM | **Not generated** |
| Signed releases | **None** |

## 6. Security / Compliance Documents

| Document | Present |
|----------|---------|
| SECURITY.md | ❌ |
| Security policy | ❌ |
| Vulnerability disclosure process | ❌ |
| SBOM | ❌ |
| Supply chain attestation | ❌ (release.yml has provenance step but never run) |
| Dependency audit (cargo-audit) | ✅ In CI, not verified locally |
| License compliance (cargo-deny) | ✅ In CI, not verified locally |

## 7. Known Build Issues

1. **`exo-gateway` binary does not compile** — Missing `tokio`, `dotenvy` dependencies; references `server::run_server` and `db` module that don't exist in the source
2. **`exo-dag` benchmark does not compile** — Stale imports referencing functions/types that no longer exist in `exo-core`
3. **Clippy fails** — `as_conversions` lint in `exo-core` (2 occurrences)
4. **fmt fails** — Import ordering in `exochain-wasm/src/serde_bridge.rs`

## 8. Repo Hygiene

| Issue | Status |
|-------|--------|
| `tools/cross-impl-test/node_modules/` tracked | ✅ Fixed in this branch |
| `tools/*/__pycache__/` tracked | ✅ Fixed in this branch |
| `web/dist/` tracked | ✅ Fixed in this branch |
| `.gitignore` coverage | ✅ Updated in this branch |

## 9. CI Gates (as declared in ci.yml)

| Gate | Name | Enforced |
|------|------|----------|
| 1 | Build (release) | `cargo build --workspace --release` |
| 2 | Test | `cargo test --workspace` + `--release` |
| 3 | Coverage (≥90%) | `cargo-tarpaulin --fail-under 90` |
| 4 | Clippy Lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| 5 | Format | `cargo +nightly fmt --all -- --check` |
| 6 | Audit | `cargo audit` |
| 7 | Deny | `cargo deny check` |
| 8 | Documentation | `cargo doc --workspace --no-deps` with `-D warnings` |

**Note**: Gates 1-2 will fail in CI due to `exo-gateway` binary. Gate 4 will fail due to clippy issues. Gate 5 will fail due to fmt issue. The "all gates pass" claim in README is currently **not true** for a clean CI run.
