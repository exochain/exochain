# Contributing to EXOCHAIN

> **The Trust Fabric for the Digital Economy**
>
> **JUDICIAL BUILD NOTICE**: This repository is not a standard open-source project. It is a **Constitutional Substrate**. All contributions are treated as "Amendments" to a living legal text.

## 1. The Judicial Build Philosophy

We do not just "write code"; we **codify law**.

EXOCHAIN is a high-assurance, verifiable, and deterministically final trust fabric. Our primary product is **proven correctness**. A bug here is not just an inconvenience; it is a breach of contract, a security failure, and potentially a violation of data sovereignty laws.

Therefore, we operate under **Strict Judicial Governance**:

1. **Verification > Trust**: We do not trust your code. We verify it.
2. **Spec is Law**: If the code disagrees with [EXOCHAIN_Specification_v2.2.pdf](./EXOCHAIN_Specification_v2.2.pdf), the *code* is wrong.
3. **Invariant Preservation**: No change may violate the Core Invariants (Identity Adjudication, Data Sovereignty, Deterministic Finality).

---

## 2. Contribution Workflow

We follow a rigorous "Legislative -> Executive -> Judicial" workflow for all changes.

```mermaid
graph LR
    subgraph Legislative [Legislative Branch]
        A[Issue / Proposal] -->|Spec Alignment| B[Traceability Matrix]
    end

    subgraph Executive [Executive Branch]
        B --> C[Draft Amendment (Code)]
        C -->|Local Test| D[Pre-verify]
    end

    subgraph Judicial [Judicial Branch]
        D -->|PR Submitted| E[Automated Bailiff (CI)]
        E -->|Pass| F[Peer Review]
        F -->|Approve| G[Security Audit]
        G -->|Sign & Seal| H[Merge / Finality]
    end

    style Legislative fill:#f4f4f4,stroke:#333
    style Executive fill:#e6f3ff,stroke:#0066cc
    style Judicial fill:#fff0f0,stroke:#cc0000
```

### Phase A: Legislative (The Issue)
* **No Code Without a Ticket**: Every PR must start with an Issue.
* **Traceability**: You must identify which section of `EXOCHAIN_Specification_v2.2.pdf` your change addresses.
* **Threat Modeling**: If you are touching `exo-core` or `exo-gatekeeper`, you must reference the relevant [Threat Model](governance/threat_matrix.md) entry.

### Phase B: Executive (The Code)
* **Rust 1.85+**: We use modern, stable Rust. Ensure your toolchain is up to date.
* **Signed Commits**: All commits **MUST** be GPG/SSH signed. Unsigned commits will be rejected by the gatekeeper.
* **Linear History**: No merge commits. Rebase on `main`.
* **Post-Quantum Awareness**: Cryptographic code must use the `Signature` enum (Ed25519/PostQuantum/Hybrid). Direct signature construction is forbidden.

### Phase C: Judicial (The Review)
* **The "No Panic" Rule**: `unwrap()`, `expect()`, and `panic!()` are **strictly forbidden** in production code. Use `Result<T, AppError>`.
* **Coverage Mandate**: **90%** line coverage is the *floor*, not the ceiling (per CR-001 Section 8.8).
* **Zero Warnings**: `cargo clippy` and `cargo audit` must be silent.
* **No Floats**: `#[deny(clippy::float_arithmetic)]` is enforced workspace-wide. Use fixed-point or integer arithmetic.

---

## 3. Development Environment

### Prerequisites
* **Rust 1.85+**: `rustup update stable`
* Clang: Required for `exo-core` crypto extensions.

For a complete setup walkthrough, see [docs/guides/GETTING-STARTED.md](docs/guides/GETTING-STARTED.md).

### AI-Assisted Development

If contributing with AI assistance, see [AGENTS.md](AGENTS.md) for sub-agent charters, instructions, and the Syntaxis Builder workflow.

### ExoForge Self-Improvement Cycle

[ExoForge](https://github.com/exochain/exoforge) is the autonomous implementation engine for ExoChain. It picks up work items from two sources:

1. **GitHub Issues** — Issues labeled `exoforge:triage` are automatically ingested via the `exoforge-triage.yml` GitHub Action
2. **Widget Feedback** — User suggestions from the demo UI's AI help menus are posted to `POST /api/feedback`

Both routes enter the governed pipeline: triage → AI-IRB council review (5 panels) → implementation → constitutional validation (8 invariants, 10 TNCs) → PR creation.

See [docs/guides/ARCHON-INTEGRATION.md](docs/guides/ARCHON-INTEGRATION.md) for details.

### Pre-commit Verification

```bash
# Verify your environment
cargo --version   # Must be 1.85+
clang --version

# Run the full test suite
cargo test --workspace --lib
cargo test --workspace --all-features
```

### The "Quality Gate" Script

Before pushing, you **MUST** pass the local quality gate:

```bash
# 1. Format
cargo fmt --all -- --check

# 2. Lint (Strict — no warnings, no float arithmetic)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Test (library tests)
cargo test --workspace --lib

# 4. Doc Test
cargo test --workspace --doc

# 5. Dependency Check (license compliance, advisories, banned crates)
cargo deny check

# 6. Security Audit
cargo audit
```

---

## 4. Pull Request Standards

Your Pull Request is a legal brief explaining why your code deserves to be part of the Constitution.

### PR Checklist

All of the following must pass before a PR can be merged:

- [ ] `cargo build --workspace --all-targets` succeeds
- [ ] `cargo test --workspace --lib` passes (0 failures)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo deny check` passes
- [ ] `cargo audit` passes
- [ ] `cargo doc --no-deps` succeeds
- [ ] Coverage >= 90% (verified by CI)

Once your change passes the PR checklist, see
[docs/guides/DEPLOYMENT.md](./docs/guides/DEPLOYMENT.md) for how the merged
binary is shipped (Railway Dockerfile, entrypoint env contract, node bootstrap).
Deployment-relevant PRs (Dockerfile, `deploy/entrypoint.sh`, `railway.json`,
`docker-compose*.yml`) should include a note linking to the deployment doc
section they exercise.

### The PR Description

Use the following template:

```markdown
## Amendment Summary
(Briefly explain what this change does)

## Legislative Basis
* **Fixes Issue**: #123
* **Spec Section**: Section 9.1 Event Hashing
* **Traceability ID**: REQ-CRYPTO-004

## Judicial Impact
* [ ] **Invariants**: Does this preserve all Core Invariants?
* [ ] **Security**: Has the Threat Model been updated?
* [ ] **Performance**: Does this impact BFT finality latency?
* [ ] **Post-Quantum**: If crypto-related, does the Signature enum handle all variants?

## Verification Evidence
* **Tests Added**: `tests/test_hashing_vectors.rs`
* **Benchmarks**: `crit/benches/hashing.rs` (if critical path)
```

### Review Process
1. **Automated Bailiff**: CI checks formatting, linting, tests, coverage, `cargo deny`, and audit.
2. **Peer Review**: Two maintainers must approve.
3. **Security Review**: Changes to `exo-core`, `exo-gatekeeper`, or `exo-consent` require specific Security Team sign-off.

---

## 5. Style & Conventions

### Rust Idioms
* **Error Handling**: Use `thiserror` for library crates, `anyhow` for binaries/cli.
* **Async/Await**: Use `tokio` exclusively. Avoid blocking operations in async contexts.
* **No Floats**: All arithmetic must use fixed-point or integer types. Float arithmetic is denied at the workspace level.
* **Documentation**:
    * Public items must have `///` doc comments.
    * Modules must have `//!` explanations.
    * Include `# Examples` in doc comments where possible.

### Naming
* **Crates**: `exo-<component>` (e.g., `exo-identity`)
* **Files**: `snake_case.rs`
* **Types**: `PascalCase`
* **Functions**: `snake_case`

---

## 6. Code of Conduct

We enforce a **Professional Standard**. We are building critical infrastructure, not a social club.

* Be precise.
* Be rigorously honest about trade-offs.
* Criticize the code, never the person.
* Uphold the [Apache 2.0 License](./LICENSE).

> **"In Code We Trust, But Only After Verification."**

---
*EXOCHAIN Foundation — Judicial Build Governance*
