---
title: "EXOCHAIN Getting Started Guide"
status: active
created: 2026-03-18
tags: [exochain, guide, getting-started, contributing]
---

# Getting Started

**Build, test, contribute to, and understand the EXOCHAIN constitutional trust fabric.**

> Cross-references: [[ARCHITECTURE]], [[CRATE-REFERENCE]], [[THREAT-MODEL]], [[CONSTITUTIONAL-PROOFS]]

---

## 1. Prerequisites

### Required Toolchain

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| **Rust** | 1.85+ | The workspace uses `edition = "2024"` and `rust-version = "1.85"` |
| **cargo-tarpaulin** | latest | Code coverage measurement (CI requires >= 90% line coverage) |
| **cargo-deny** | latest | License, advisory, and dependency governance |
| **cargo-audit** | latest | Known vulnerability scanning |

### Installation

```bash
# Install Rust via rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify Rust version
rustc --version  # Must be >= 1.85.0

# Install quality gate tools
cargo install cargo-tarpaulin
cargo install cargo-deny
cargo install cargo-audit
```

### Optional but Recommended

| Tool | Purpose |
|------|---------|
| `cargo-watch` | Auto-rebuild on file changes: `cargo watch -x test` |
| `cargo-expand` | Macro expansion debugging |
| `python3` | Required for `tools/codegen/` and `tools/syntaxis/` |

---

## 2. Clone and Build

```bash
# Clone the repository
git clone https://github.com/exochain/exochain.git
cd exochain

# Build all 16 crates (debug mode)
cargo build --workspace

# Build in release mode (LTO enabled, may take longer)
cargo build --workspace --release
```

The workspace compiles all 16 crates and their dependencies. The first build downloads and compiles external dependencies (ed25519-dalek, blake3, serde, etc.). Subsequent builds are incremental.

### Build Verification

A clean build should produce:

- Zero errors
- Zero warnings (clippy is set to deny warnings in CI)
- All 16 crates compiled

```bash
# Verify no warnings
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 3. Run Tests

```bash
# Run all 1,846 tests across 16 crates
cargo test --workspace

# Run tests for a specific crate
cargo test -p exo-core
cargo test -p exo-gatekeeper

# Run tests with output (useful for debugging)
cargo test --workspace -- --nocapture

# Run a specific test by name
cargo test -p exo-core bcts_transition_happy_path

# Run property-based tests (proptest)
cargo test --workspace -- --include-ignored
```

### Expected Output

All 1,846 tests should pass with 0 failures:

```
test result: ok. 1846 passed; 0 failed; 0 ignored
```

### Coverage

```bash
# Generate coverage report
cargo tarpaulin --workspace --out html

# Open the report
open tarpaulin-report.html
```

CI requires a minimum of 90% line coverage. If adding new code, ensure coverage does not drop below this threshold.

---

## 4. Understanding the Architecture

Before contributing, read the [[ARCHITECTURE]] document. Key concepts:

### The Three Branches

EXOCHAIN implements a separation-of-powers model inspired by constitutional governance:

| Branch | Crate | Role |
|--------|-------|------|
| **Judicial** | `exo-gatekeeper` | Immutable kernel that adjudicates all actions against the 8 constitutional invariants |
| **Legislative** | `exo-governance` | Quorum-based decision making with independence-aware voting |
| **Executive** | `exo-consent`, `exo-authority` | Consent enforcement and delegated authority chains |

### The BCTS Transaction Lifecycle

Every operation in EXOCHAIN follows the Bailment-Conditioned Transaction Set (BCTS) state machine defined in `exo-core::bcts`:

```
Draft -> Submitted -> IdentityResolved -> ConsentValidated -> Deliberated
-> Verified -> Governed -> Approved -> Executed -> Recorded -> Closed
```

Each transition produces a cryptographic receipt. The receipt chain is verifiable end-to-end. See [[CRATE-REFERENCE]] Section 1 (`exo-core::bcts`) for the full state diagram.

### The Dependency Graph

```
exo-core (root)
├── exo-identity, exo-consent, exo-dag, exo-proofs, exo-authority
├── exo-gatekeeper
├── exo-governance, exo-escalation, exo-legal
├── exo-tenant, exo-api, exo-gateway
└── decision-forum
```

All crates depend on `exo-core`. See [[CRATE-REFERENCE]] for the complete dependency map.

---

## 5. Your First Contribution

### 5.1 How to Add a New Invariant

The eight constitutional invariants are defined in `exo-gatekeeper`. To add a ninth:

**Step 1.** Add the variant to `ConstitutionalInvariant` in `crates/exo-gatekeeper/src/invariants.rs`:

```rust
pub enum ConstitutionalInvariant {
    SeparationOfPowers,
    ConsentRequired,
    NoSelfGrant,
    HumanOverride,
    KernelImmutability,
    AuthorityChainValid,
    QuorumLegitimate,
    ProvenanceVerifiable,
    YourNewInvariant,       // <-- add here
}
```

**Step 2.** Add it to `InvariantSet::all()` so it is enforced by default.

**Step 3.** Implement the check logic in `InvariantEngine::check()`. The check receives an `InvariantContext` with actor info, consent state, authority chain, and action details.

**Step 4.** Add the invariant to the kernel's adjudication loop in `crates/exo-gatekeeper/src/kernel.rs`.

**Step 5.** Write tests proving the invariant:
- Holds for valid operations
- Rejects violating operations
- Cannot be bypassed by any combination of actor roles
- Produces a detailed `InvariantViolation` with evidence

**Step 6.** Update `tools/syntaxis/node_registry.json` to reference the new invariant in all node types it applies to.

**Step 7.** Submit a governance proposal under `governance/resolutions/` documenting the invariant's constitutional basis and rationale.

### 5.2 How to Add a New Combinator

Combinators live in `exo-gatekeeper::combinator`. The current algebra includes: Identity, Sequence, Parallel, Choice, Guard, Transform, Retry, Timeout, Checkpoint.

**Step 1.** Add the variant to the `Combinator` enum in `crates/exo-gatekeeper/src/combinator.rs`:

```rust
pub enum Combinator {
    Identity,
    Sequence(Vec<Combinator>),
    // ... existing variants ...
    YourCombinator(Box<Combinator>, YourConfig),
}
```

**Step 2.** Implement the reduction case in the `reduce()` function. Reduction must be pure: the same input always produces the same output.

**Step 3.** Write tests proving:
- Deterministic reduction (same input -> same output across runs)
- Composition with other combinators (e.g., `Sequence([YourCombinator, Identity])`)
- Error propagation behavior
- Interaction with Guard predicates

**Step 4.** Update `tools/syntaxis/node_registry.json` if the combinator should be available in the visual workflow builder.

### 5.3 How to Add a New Crate

Use the scaffolding generator in `tools/codegen/`:

```bash
python3 tools/codegen/generate_crate.py exo-newcrate module1 module2 module3
```

This generates:
- `crates/exo-newcrate/Cargo.toml` linked to workspace dependencies
- `crates/exo-newcrate/src/lib.rs` with module declarations and re-exports
- `crates/exo-newcrate/src/error.rs` with typed error variants
- `crates/exo-newcrate/src/<module>.rs` with struct, trait, and test skeleton
- `crates/exo-newcrate/tests/<module>_tests.rs` integration tests

The generator also adds the crate to the workspace `Cargo.toml` members list.

**After generation:**

```bash
# Verify the crate builds
cargo build -p exo-newcrate

# Verify tests pass
cargo test -p exo-newcrate

# Verify no clippy warnings
cargo clippy -p exo-newcrate -- -D warnings
```

Then customize the generated types for your domain, add the crate to the dependency graph in the appropriate position, and ensure all eight invariants are addressed where applicable.

---

## 6. Constitutional Constraints You Must Follow

These constraints are non-negotiable. Every change must satisfy all of them. Violations are rejected by CI and by the kernel at runtime.

### 6.1 No Floating-Point Arithmetic

```rust
// FORBIDDEN — will not compile
let x: f64 = 3.14;
let y = x * 2.0;

// CORRECT — use integer arithmetic or basis points
let x_bp: u64 = 31_400;  // 3.14 in basis points (1/10000)
let y_bp = x_bp * 2;
```

The workspace denies `clippy::float_arithmetic`, `clippy::float_cmp`, and `clippy::float_cmp_const`. Floating-point is inherently non-deterministic across platforms (rounding, NaN handling, denormals). Use basis points (1/10,000) or millibels for fractional values.

### 6.2 No HashMap

```rust
// FORBIDDEN — non-deterministic iteration order
use std::collections::HashMap;
let mut map = HashMap::new();

// CORRECT — deterministic iteration order
use std::collections::BTreeMap;
let mut map = BTreeMap::new();

// Or use the alias from exo-core
use exo_core::DeterministicMap;
let mut map: DeterministicMap<String, String> = DeterministicMap::new();
```

`HashMap` and `HashSet` have non-deterministic iteration order. Use `BTreeMap` and `BTreeSet` exclusively. The `DeterministicMap` alias from `exo-core` makes the intent explicit.

### 6.3 No Unsafe Code

```rust
// FORBIDDEN — workspace denies unsafe_code
unsafe { std::ptr::read(ptr) }

// CORRECT — use safe abstractions only
```

The workspace sets `unsafe_code = "deny"` in `[workspace.lints.rust]`. If you believe unsafe is required, document the justification and request a constitutional amendment through the governance process.

### 6.4 Every Public Function Needs Tests

Every public function, method, and trait implementation must have at least one test proving it works correctly. Property-based tests using `proptest` are encouraged for functions with complex input spaces.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_function_happy_path() {
        let result = my_function("valid input");
        assert!(result.is_ok());
    }

    #[test]
    fn my_function_rejects_empty() {
        let result = my_function("");
        assert!(result.is_err());
    }
}
```

### 6.5 Every New Feature Needs an Invariant Check

If your feature introduces a new operation type, ensure it is:
1. Adjudicated by the kernel (all 8 invariants checked)
2. Covered by consent (requires an active bailment)
3. Attributed to an actor (provenance verifiable)
4. Recorded in the audit trail

### 6.6 Additional Rules

- **No system time.** Use `exo_core::hlc::HybridClock` for all timestamps. Never call `std::time::SystemTime::now()` or `Instant::now()` in production code.
- **No randomness in logic.** Randomness is only permitted for key generation. All governance logic must be purely deterministic.
- **Canonical serialization.** All data that gets hashed must be serialized via CBOR using `ciborium` with sorted keys. Never hash JSON directly.
- **Error context.** Every error variant must carry enough context to diagnose the failure without access to the source code. Use `thiserror` for all error types.

---

## 7. Running the Full Quality Gate Locally

Before pushing, run all 8 quality gates that CI enforces per [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] Section 8.8:

```bash
# 1. Build (release mode)
cargo build --workspace --release

# 2. Test (all 1,846 tests)
cargo test --workspace

# 3. Coverage (minimum 90%)
cargo tarpaulin --workspace

# 4. Lint (zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# 5. Format check
cargo fmt --all -- --check

# 6. Security audit
cargo audit

# 7. Dependency governance (license + advisory)
cargo deny check

# 8. Documentation (no warnings)
cargo doc --workspace --no-deps
```

**One-liner for quick validation:**

```bash
cargo build --workspace --release && \
cargo test --workspace && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo fmt --all -- --check && \
cargo doc --workspace --no-deps
```

If any gate fails, the CI pipeline will reject the PR. Fix all issues locally before pushing.

### Cross-Implementation Consistency

For changes that affect determinism-critical code, run the cross-implementation test:

```bash
./tools/cross-impl-test/compare.sh
```

This verifies that the same inputs produce identical outputs across implementations.

---

## 8. Understanding the Council Process

EXOCHAIN changes that affect constitutional properties require a council assessment. This is not bureaucracy -- it is the mechanism that ensures the trust fabric remains trustworthy.

### When Is a Council Assessment Required?

- Adding or modifying a constitutional invariant
- Changing the kernel adjudication logic
- Modifying the BCTS state machine
- Adding new cryptographic primitives
- Changing the consensus protocol
- Any change that affects determinism guarantees

### How to Submit a Resolution

1. Create a resolution file under `governance/resolutions/`:

```markdown
---
title: "CR-XXX: Your Resolution Title"
status: proposed
author: your-did
created: YYYY-MM-DD
---

# CR-XXX: Your Resolution Title

## Summary
One paragraph describing the change.

## Constitutional Impact
Which invariants are affected and how.

## Determinism Analysis
How determinism is preserved.

## Threat Analysis
What new attack vectors are introduced (if any).
Reference the [[THREAT-MODEL]] taxonomy.

## Separation of Powers
How the change interacts with the three branches.

## Consent Impact
Whether consent requirements change.
```

2. Run all quality gates (Section 7 above).

3. Submit as a PR. The CI pipeline enforces the same gates automatically.

4. The council reviews the resolution against the constitutional framework defined in [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]].

### Existing Council Documents

- [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] -- Foundational council resolution defining AEGIS and the Sybil threat taxonomy
- [[COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN]] -- 5-panel assessment that drove the refactor from EXO to EXOCHAIN
- [[EXOCHAIN-REFACTOR-PLAN]] -- Master plan: council -> Syntaxis -> assimilation

---

## Quick Reference

| Task | Command |
|------|---------|
| Build all | `cargo build --workspace` |
| Test all | `cargo test --workspace` |
| Test one crate | `cargo test -p exo-core` |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Format | `cargo fmt --all` |
| Format check | `cargo fmt --all -- --check` |
| Coverage | `cargo tarpaulin --workspace --out html` |
| Audit | `cargo audit` |
| Deny check | `cargo deny check` |
| Docs | `cargo doc --workspace --no-deps --open` |
| New crate | `python3 tools/codegen/generate_crate.py exo-name mod1 mod2` |
| Cross-impl test | `./tools/cross-impl-test/compare.sh` |

---

> For the full API surface see [[CRATE-REFERENCE]]. For the threat model see [[THREAT-MODEL]]. For formal proofs of constitutional properties see [[CONSTITUTIONAL-PROOFS]].
