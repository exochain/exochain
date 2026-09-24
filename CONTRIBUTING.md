<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

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
3. **Security Review**: Security-sensitive changes, including changes to `exo-core`, `exo-gatekeeper`, or `exo-consent`, require technical security audit evidence and human maintainer review of its findings before merge, under the accountability described below.

#### Beta repository maintainers

For repository review during beta, **Bob Stewart (`@bob-stewart`), Max Stewart
(`@mstewartbz`), and Robert (`@robst3w`)** are the responsible maintainers for
each of **Architecture, Governance, and Operations**. These are repository
maintenance responsibilities, not appointments to constitutional council seats.
The same roster covers all three areas; it is not three independent electorates.
Bob Stewart is accountable for security and legal/compliance matters. EXOCHAIN
has no separate Legal department or Legal reviewer role during beta. These paths
route to the same real maintainers for independent review; that routing neither
makes them legal professionals nor transfers Bob's accountability.
See the [beta ownership correction](governance/resolutions/BETA-MAINTAINER-OWNERSHIP.md)
for scope, adoption conditions, and the recorded release-review chronology.

- Two distinct, independent human maintainers must approve the final candidate
  commit before merge. The PR author cannot approve their own change. One human
  counts once, even when covering several areas. Agent reviews are supporting
  evidence and do not count as human approvals.
- A named maintainer's review may cover all affected Architecture, Governance,
  and Operations paths; that area coverage does not require additional votes
  beyond the two independent maintainer approvals. Partial or qualified reviews
  must identify their scope and unresolved conditions.
- Security audits use **Daybreak and other security review systems**, selected
  for the changed surface. No single tool is the exclusive or mandatory source
  of audit evidence. Record the audited source revision, scope, actual findings,
  remediation/disposition, and verification evidence. Existing relevant audits
  may be reused when their source/scope applicability is demonstrated; do not
  rerun an audit solely because ownership wording changed. Tool output does not
  approve a PR or discharge human accountability. Bob is accountable for finding
  disposition; the independent maintainer reviewers verify that disposition.
  His disposition of findings in his own PR is not an independent approval.
- License, dependency, consent, privacy, and other applicable compliance checks
  remain required. Maintainers review the evidence under Bob's accountability;
  no approval is required from a nonexistent Legal department. This does not
  change legal obligations, represent a legal opinion, or alter runtime consent
  or authority rules.
- Multiple owners on one CODEOWNERS line are alternatives in GitHub, not an
  enforced quorum; later matching rules replace earlier ones. Written review
  and audit requirements still apply in addition to automatic review routing.
- This roster does not grant repository, organization, runtime, or publisher
  permissions. Required CI, branch protections, signing, protected release
  environment approvals, custody, provenance, expiry checks, dry/live separation,
  and independent publication acceptance remain unchanged. Beta or ad hoc release
  scheduling is not an exception to these safeguards.
- Adoption is prospective through reviewed integration of this correction.
  Post-merge reviews retain their actual timestamps and do not retroactively
  satisfy a pre-merge requirement or authorize a release-policy waiver.

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
