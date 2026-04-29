---
title: "EXOCHAIN Getting Started"
status: active
created: 2026-03-18
updated: 2026-04-15
tags: [exochain, guide, getting-started, contributing]
---

# Getting Started

**You have 5 minutes. Pick your path.**

EXOCHAIN is a constitutional trust fabric: every action is adjudicated by an immutable kernel that enforces 8 invariants (consent required, no self-grant, kernel immutability, ...) before it takes effect. The fabric ships a Rust canonical implementation, two SDKs (TypeScript, Python), and an MCP server that lets AI agents operate inside the constitution.

> Cross-references: [[ARCHITECTURE]], [[CRATE-REFERENCE]], [[THREAT-MODEL]], [[CONSTITUTIONAL-PROOFS]]

---

## Table of Contents

- [3-step quickstart](#3-step-quickstart)
- [Pick your path](#pick-your-path)
- [Prerequisites (for building)](#prerequisites-for-building)
- [Build, test, lint](#build-test-lint)
- [Architecture in 60 seconds](#architecture-in-60-seconds)
- [Contributing changes](#contributing-changes)
- [Constitutional constraints](#constitutional-constraints)
- [Running the full quality gate locally](#running-the-full-quality-gate-locally)
- [Council process for constitutional changes](#council-process-for-constitutional-changes)
- [Quick reference](#quick-reference)

---

## 3-step quickstart

```bash
# 1. Clone
git clone https://github.com/exochain/exochain.git
cd exochain

# 2. Build the node + SDK (release mode)
cargo build --release -p exo-node -p exochain-sdk

# 3. Launch the MCP server (stdio)
./target/release/exochain mcp
```

Expected output on stderr:

```text
[exochain-mcp] Constitutional MCP server ready on stdio
[exochain-mcp] Actor: did:exo:<your-node-identity>
[exochain-mcp] Tools: 40
```

That's it — you have a constitutional node running with 40 MCP tools, 6 resources, and 4 prompts. Point a Claude Code config at the binary (see the MCP guide below) and an AI agent can now drive governance operations under the kernel.

---

## Pick your path

| I want to... | Start here | One-liner |
|---|---|---|
| **Build a Rust app on the fabric** | [Rust SDK Quickstart](./sdk-quickstart-rust.md) | `cargo add exochain-sdk` |
| **Build a TS/JS app (Node or browser)** | [TypeScript SDK Quickstart](./sdk-quickstart-typescript.md) | `npm install @exochain/sdk` |
| **Build a Python service** | [Python SDK Quickstart](./sdk-quickstart-python.md) | `pip install exochain` |
| **Let Claude (or any AI) drive the fabric** | [MCP Integration Guide](./mcp-integration.md) | `exochain mcp` |
| **Run a node (operator)** | [Deployment Guide](./DEPLOYMENT.md) | `exochain start --api-port 8080` |
| **Join an existing network** | [Deployment Guide](./DEPLOYMENT.md) | `exochain join --seed <host:port>` |
| **Understand the architecture** | [Architecture](../architecture/ARCHITECTURE.md) | — |
| **Integrate with ExoForge** | [Archon Integration](./ARCHON-INTEGRATION.md) | — |
| **Contribute a new feature** | [Contributing section below](#contributing-changes) | `cargo test --workspace` |

---

## Prerequisites (for building)

| Tool | Minimum | Purpose |
|---|---|---|
| **Rust** | 1.85+ (edition 2024) | Core workspace |
| **cargo-tarpaulin** | latest | Coverage (CI requires >=90%) |
| **cargo-deny** | latest | License + advisory + source governance |
| **cargo-audit** | latest | Known-vulnerability scanning |
| **Node 20+** *(optional)* | | TypeScript SDK |
| **Python 3.11+** *(optional)* | | Python SDK + codegen tools |

Install:

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version  # must be >= 1.85.0

# Quality gate tools
cargo install cargo-tarpaulin
cargo install cargo-deny
cargo install cargo-audit
```

---

## Build, test, lint

```bash
# Build the full workspace (debug)
cargo build --workspace

# Build in release mode (LTO, may take longer)
cargo build --workspace --release

# Run the workspace test gate
cargo test --workspace

# Run tests for a specific crate
cargo test -p exochain-sdk
cargo test -p exo-gatekeeper

# Lint (zero warnings — CI denies)
cargo clippy --workspace --all-targets -- -D warnings

# Coverage (HTML report)
cargo tarpaulin --workspace --out html
open tarpaulin-report.html
```

A clean build produces zero errors and zero warnings. The current workspace
inventory lists 2,972 tests; the exact executed count can change as doctests and
integration targets evolve. What matters is zero failures:

```
test result: ok. ... passed; 0 failed; 0 ignored
```

---

## Architecture in 60 seconds

EXOCHAIN separates powers across three crate families:

| Branch | Crate | Role |
|---|---|---|
| **Judicial** | `exo-gatekeeper` | Immutable kernel adjudicating actions against 8 invariants. |
| **Legislative** | `exo-governance` | Quorum-based decisions with independence-aware voting. |
| **Executive** | `exo-consent`, `exo-authority` | Consent enforcement + delegated authority chains. |

Every operation flows through the BCTS (Bailment-Conditioned Transaction Set) state machine in `exo-core::bcts`:

```
Draft -> Submitted -> IdentityResolved -> ConsentValidated -> Deliberated
-> Verified -> Governed -> Approved -> Executed -> Recorded -> Closed
```

Each transition emits a cryptographic receipt; the receipt chain is verifiable end-to-end.

All workspace crates depend directly or indirectly on `exo-core`. The full dependency graph is in [[ARCHITECTURE]]; the API surface is in [[CRATE-REFERENCE]]; the formal proof material is in [[CONSTITUTIONAL-PROOFS]].

---

## Contributing changes

### Add a new invariant

The 8 invariants live in `crates/exo-gatekeeper/src/invariants.rs`. To add a 9th:

1. Extend the `ConstitutionalInvariant` enum.
2. Add it to `InvariantSet::all()` so it is enforced by default.
3. Implement the check in `InvariantEngine::check()` against `InvariantContext`.
4. Add to the kernel adjudication loop in `crates/exo-gatekeeper/src/kernel.rs`.
5. Write tests proving the invariant holds, rejects violations, and cannot be bypassed.
6. Update `tools/syntaxis/node_registry.json` if the invariant should be visible to Syntaxis.
7. Submit a council resolution under `governance/resolutions/` documenting the rationale.

### Add a new combinator

Combinators live in `exo-gatekeeper::combinator`. Add the variant, implement deterministic reduction, write composition tests, update `node_registry.json`.

### Scaffold a new crate

```bash
python3 tools/codegen/generate_crate.py exo-newcrate module1 module2 module3
```

This generates `Cargo.toml`, `lib.rs`, `error.rs`, per-module source + test skeletons, and adds the crate to the workspace.

```bash
cargo build -p exo-newcrate
cargo test  -p exo-newcrate
cargo clippy -p exo-newcrate -- -D warnings
```

---

## Constitutional constraints

These are non-negotiable. CI rejects violations; the kernel rejects them at runtime.

### No floating-point arithmetic

```rust
// FORBIDDEN
let x: f64 = 3.14;
let y = x * 2.0;

// CORRECT — basis points
let x_bp: u64 = 31_400;      // 3.14 in basis points (1/10_000)
let y_bp = x_bp * 2;
```

The workspace denies `clippy::float_arithmetic`, `clippy::float_cmp`, and `clippy::float_cmp_const`. Floating-point is non-deterministic across platforms.

### No HashMap

```rust
// FORBIDDEN — non-deterministic iteration order
use std::collections::HashMap;

// CORRECT
use std::collections::BTreeMap;
use exo_core::DeterministicMap;   // type alias for BTreeMap
```

### No unsafe code

```rust
// FORBIDDEN
unsafe { ... }
```

`unsafe_code = "deny"` is set in `[workspace.lints.rust]`. If you think you need `unsafe`, propose a council amendment.

### Every public function needs tests

Every public fn / method / trait impl must have at least one test. Property-based tests via `proptest` are encouraged for complex input spaces.

### Every new feature needs an invariant check

A new operation type must be:

1. Adjudicated by the kernel (all 8 invariants).
2. Covered by consent (requires an active bailment).
3. Attributed to an actor (provenance verifiable).
4. Recorded in the audit trail.

### Other rules

- **No system time.** Use `exo_core::hlc::HybridClock`. Never call `SystemTime::now()` or `Instant::now()` in production code.
- **No randomness in logic.** Randomness is permitted only for key generation.
- **Canonical serialization.** Hash CBOR (via `ciborium`) with sorted keys, not JSON.
- **Error context.** Every error variant carries enough context to diagnose the failure from the error alone. Use `thiserror`.

---

## Running the full quality gate locally

Before pushing, run the core local checks behind the CI gates tracked against [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] §8.8:

```bash
cargo build --workspace --release
cargo test --workspace
cargo tarpaulin --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
cargo doc --workspace --no-deps
```

One-liner for quick validation:

```bash
cargo build --workspace --release && \
cargo test --workspace && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo fmt --all -- --check && \
cargo doc --workspace --no-deps
```

### Cross-implementation consistency

For determinism-critical changes:

```bash
./tools/cross-impl-test/compare.sh
```

Verifies identical inputs produce identical outputs across Rust, TypeScript, and Python.

---

## Council process for constitutional changes

Changes that affect constitutional properties require a council resolution. This is not bureaucracy — it is the mechanism that keeps the trust fabric trustworthy.

**When required:**

- Adding or modifying an invariant
- Changing the kernel adjudication logic
- Modifying the BCTS state machine
- Adding new cryptographic primitives
- Changing the consensus protocol
- Any change that affects determinism guarantees

**Submission**: create a file under `governance/resolutions/` with this header:

```markdown
---
title: "CR-XXX: Your Resolution Title"
status: proposed
author: your-did
created: YYYY-MM-DD
---

# CR-XXX: Your Resolution Title

## Summary
## Constitutional Impact
## Determinism Analysis
## Threat Analysis    (reference [[THREAT-MODEL]])
## Separation of Powers
## Consent Impact
```

Run all quality gates, submit as a PR, council reviews against [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]].

Existing resolutions:

- [[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]] — Foundational council resolution defining AEGIS and the Sybil threat taxonomy
- [[COUNCIL-ASSESSMENT-EXO-VS-EXOCHAIN]] — 5-panel assessment that drove the EXO -> EXOCHAIN refactor
- [[EXOCHAIN-REFACTOR-PLAN]] — Master plan: council -> Syntaxis -> assimilation

---

## Quick reference

| Task | Command |
|---|---|
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
| Run MCP server (stdio) | `exochain mcp` |
| Run MCP server (SSE) | `exochain mcp --sse 127.0.0.1:3030` |
| Start a node | `exochain start --api-port 8080` |
| Join a network | `exochain join --seed seed.exochain.io:4001` |
| New crate | `python3 tools/codegen/generate_crate.py exo-name mod1 mod2` |
| Cross-impl test | `./tools/cross-impl-test/compare.sh` |

---

> For the full API surface see [[CRATE-REFERENCE]]. For the threat model see [[THREAT-MODEL]]. For formal proofs of constitutional properties see [[CONSTITUTIONAL-PROOFS]].

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
