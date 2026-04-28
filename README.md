# EXOCHAIN v2.2

> **Trust Fabric for the Digital Economy**
>
> *Spec Revision 2.2 — Green-Field Implementation*

EXOCHAIN is a verifiable, privacy-preserving substrate enabling secure identity adjudication, data sovereignty, and deterministic finality. Built in Rust with absolute determinism, constitutional governance, and post-quantum readiness.

## Repo Status

> Run `bash tools/repo_truth.sh` to regenerate these numbers from source.
>
> The crate count includes `exo-catapult`, `exo-consensus`, `exo-messaging`, and `exochain-sdk` (four crates previously not listed in this README).

| Metric | Value | Source |
|--------|-------|--------|
| Rust crates | 20 | `ls -d crates/*/` |
| Rust source files | 266 | `find crates -name '*.rs'` |
| Rust LOC | 120904 | `wc -l` |
| Workspace tests | 2,929 listed | `cargo test --workspace -- --list` |
| CI quality gates | 20 | `.github/workflows/ci.yml` numbered gates, plus required aggregator |
| Published releases | None (pre-release) | `git tag -l` |
| License | Apache-2.0 | `Cargo.toml` |
| Live node | https://exochain.io | Fly.io deployment |

### What is verified today

- **2,929 workspace tests are listed** by `cargo test --workspace -- --list`; CI Gate 2 runs them in debug and release modes
- **Build succeeds** for all library crates, binaries, tests, and benchmarks
- **Clippy clean** under `-D warnings` for production code
- **Format clean** under `cargo +nightly fmt --all -- --check`
- **20 numbered CI quality gates** plus the required "All Constitutional Gates" aggregator are defined and enforced
- **Traceability matrix** maps 86 requirements — see `governance/traceability_matrix.md`
- **Threat model** covers 14 threats tracked: 14 mitigated, 0 partial, 0 planned — see `governance/threat_matrix.md`
- **Constitutional invariants** enforced via the CGR kernel in all governance paths
- **No floating-point arithmetic** — denied workspace-wide via `#[deny(clippy::float_arithmetic)]`
- **Post-Quantum signatures** — NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium) via `ml-dsa` 0.1.0-rc.7, fully wired in `Signature::PostQuantum` and `Signature::Hybrid` with deterministic signing, tamper-rejection tests, proptest roundtrip coverage, and RUSTSEC-2025-0144 patch

### What is supported by design but not yet production-hardened

- **90% coverage threshold** — configured in CI via cargo-tarpaulin; not independently verified outside CI
- **exo-gateway binary** — operational HTTP server with 28 endpoints (REST, GraphQL, health probes); production hardening ongoing
- **GraphQL API** — types and schema stubs exist in `exo-api`; async runtime integration pending
- **exo-dag benchmark** — disabled; needs rewrite against current API

### In Progress

- Continuous governance monitoring via ExoForge — schema, API, threat model, and traceability complete (EXOCHAIN-REM-009); ExoForge scheduled trigger and React health dashboard pending

### Roadmap / Planned

- First versioned release (see `.github/workflows/release.yml` for the dry-run workflow)
- SBOM generation and supply-chain attestation
- Agent passport API and trust receipt endpoints on exo-node
- National AI Policy Framework compliance extensions

## Architecture

```
Layer 1: CGR Kernel         (Rust, 20 crates, 120904 tracked LOC under crates/)
         Constitutional governance runtime — deterministic, no floats,
         cryptographic proofs, 2,929 listed workspace tests

Layer 2: WASM Bridge        (packages/exochain-wasm/)
         141 verified bridge exports — Rust → WebAssembly → JavaScript

Layer 3: CommandBase.ai     (command-base/)
         Operational hypervisor for cognitiveplane.ai
         Real control surfaces, GSD buttons, governance receipts
         104 AI agents under constitutional authority
         Express/Node.js + SQLite + WebSocket

Layer 4: Decision Forum     (web/)
         Governance deliberation UI
         React/Vite — decisions, delegations, audit, constitution

Layer 5: ExoForge           (exoforge/)
         Governance triage, planning, validation, and monitoring tools
         Triage → Council-style heuristic review → Plan → Constitutional Validation
```

## The Five Axioms

1. **Identity Adjudication** — Decentralized identity with cryptographic proof, not administrative fiat.
2. **Data Sovereignty** — Data belongs to its subject; consent is explicit, revocable, and auditable.
3. **Deterministic Finality** — Every operation is reproducible and verifiable; no floating-point arithmetic permitted.
4. **Constitutional Governance** — System behavior is governed by the constitutional specification and draft CR-001 AEGIS/SYBIL framework pending council ratification.
5. **Authentic Plurality** — Sybil-resistant participation ensuring one-entity-one-voice integrity.

## Repository Structure

### Core Crates (20)

| Crate | Description |
|-------|-------------|
| `exo-core` | Cryptographic primitives (BLAKE3, Ed25519, post-quantum), Canonical CBOR, HLC |
| `exo-governance` | Constitutional governance engine, AEGIS framework, council process |
| `exo-gatekeeper` | TEE/Enclave interfaces, attestation verification, kernel invariants, holon, MCP |
| `exo-dag` | Directed Acyclic Graph engine, BFT consensus adapter, checkpointing, HLC |
| `exo-gateway` | External gateway: REST, GraphQL, auth, health probes (28 endpoints) |
| `exo-identity` | Decentralized Identity (DID), key management, Shamir secret sharing, vault |
| `exo-proofs` | SNARK, STARK, ZKML proof systems, verifier infrastructure |
| `exo-authority` | Authority delegation, role-based access, attestation chains |
| `exo-legal` | Legal compliance, audit admissibility, provenance tracking |
| `exo-consent` | Bailment contracts, consent policies, gatekeeper enforcement |
| `exo-escalation` | Escalation workflows, dispute resolution, threshold triggers |
| `exo-tenant` | Multi-tenancy isolation and tenant lifecycle management |
| `exo-api` | Public API surface and type exports |
| `decision-forum` | Governance application: council-driven decision making |
| `exochain-wasm` | WASM compilation target for browser/Node.js integration |
| `exo-node` | Distributed P2P node: BFT consensus, networking, governance API, live dashboard |
| `exo-catapult` | Franchise/NewCo spawn, budgets, goals, agents, receipts, and autonomous corporation scaffolding |
| `exo-messaging` | Encrypted messaging envelopes, death-trigger checks, and compose/open flows |
| `exo-consensus` | Multi-model consensus session, scoring, commitment, and report primitives |
| `exochain-sdk` | Rust SDK facade for identity, consent, authority, governance, and kernel calls |

### Governance & Infrastructure

* **`governance/`** — Council resolutions, sub-agent charters, traceability matrices, quality gates
* **`docs/`** — Architecture, guides, council panel reports, proofs, reference documentation
* **`.github/workflows/`** — CI pipeline (20 numbered quality gates plus required aggregator), release workflow, ExoForge triage

## Governance & Compliance

This repository is managed under strict **Judicial Build Governance**. All contributions must align with `EXOCHAIN_Specification_v2.2.pdf`. CR-001 (AEGIS/SYBIL/Authentic Plurality) is **DRAFT — pending council ratification**.

### Key Governance Artifacts

* [Traceability Matrix](governance/traceability_matrix.md) — 86 requirements tracked
* [Threat Model](governance/threat_matrix.md) — 14 mitigated, 0 partial, 0 planned
* [Quality Gates](governance/quality_gates.md) — 20 numbered CI gates plus required aggregator
* [Sub-Agent Charters](governance/sub_agents.md) — 11 agent charters documented
* [Council Resolutions](governance/resolutions/INDEX.md) — CR-001 DRAFT
* [Tier-One Readiness Audit](docs/audit/TIER-ONE-READINESS-AUDIT.md) — capability model, gap analysis, exit checklist
* [Refactor Plan](governance/EXOCHAIN-REFACTOR-PLAN.md)

### Documentation

* [Architecture](docs/architecture/ARCHITECTURE.md)
* [Threat Model](docs/architecture/THREAT-MODEL.md)
* [Getting Started Guide](docs/guides/GETTING-STARTED.md)
* [ExoForge Integration](docs/guides/ARCHON-INTEGRATION.md)
* [Deployment Guide](docs/guides/DEPLOYMENT.md)
* [Crate Reference](docs/reference/CRATE-REFERENCE.md)
* [Constitutional Proofs](docs/proofs/CONSTITUTIONAL-PROOFS.md)
* [Council Panel Reports](docs/council/) — 5-panel assessment
* [Licensing Position](docs/legal/LICENSING-POSITION.md)
* [Repo Truth Baseline](docs/audit/REPO-TRUTH-BASELINE.md)

## Demo Platform

The `demo/` directory contains a full-stack governance-conditioned execution platform:

- **7 Node.js microservices** — Identity, consent, governance, decision-making, auditing, provenance, and API gateway
- **React web UI** — 12-column configurable drag-and-drop widget grid across 6 pages with context-sensitive AI help menus
- **Rust→WASM engine** — 45 exported governance functions compiled via wasm-pack
- **PostgreSQL** — Persistent governance state, audit trails, and provenance records

```bash
cd demo && npm install && npm run dev
# Web UI: http://localhost:5173
# API:    http://localhost:3000
```

See [demo/README.md](demo/README.md) for full setup instructions.

## ExoForge

[ExoForge](exoforge/) provides governance triage, planning, validation, and monitoring tools for ExoChain:

```
Widget AI Help → Feedback Ingestion → Triage → Council-Style Heuristic Review → Implementation Plan → Constitutional Validation
```

- **7 Archon commands** — Triage, council-style review, Syntaxis generation, PRD generation, implementation planning, bug-fix planning, constitutional validation
- **4 DAG workflows** — Self-improvement cycle, client onboarding, issue fixing, continuous governance monitoring
- **5×5 discipline matrix** — 5 council panels × 5 artifact properties (Storable, Diffable, Transferable, Auditable, Contestable)
- **GitHub Issues integration** — Issues labeled `exoforge:triage` automatically enter the self-improvement cycle

See [docs/guides/ARCHON-INTEGRATION.md](docs/guides/ARCHON-INTEGRATION.md) for setup and usage.

## Getting Started

### Prerequisites

* **Rust 1.85+** (`rustup update stable`)
* Clang (for crypto extensions)

### Build & Test

```bash
# Build all crates
cargo build --workspace --all-targets

# Run the workspace test gate
cargo test --workspace

# Lint (strict — no warnings allowed)
cargo clippy --workspace --lib --bins -- -D warnings

# Format check
cargo +nightly fmt --all -- --check

# Dependency audit (requires cargo-deny)
cargo deny check

# Regenerate truth baseline
bash tools/repo_truth.sh
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full judicial build workflow.

1. **Safety**: No PII on ledger. No admins. No floating-point arithmetic.
2. **Quality**: No Clippy warnings in production code. All CI quality gates must pass.
3. **Process**: All PRs should map to a Spec requirement. See [AGENTS.md](AGENTS.md) for AI-assisted development.

## Post-Quantum Cryptography

EXOCHAIN uses a `Signature` enum supporting three modes:

* **Ed25519** — Current default for signing and verification
* **PostQuantum** — NIST FIPS 204 ML-DSA-65 (CRYSTALS-Dilithium). Production-wired.
* **Hybrid** — Combined Ed25519 + ML-DSA-65. Strict AND verification (no short-circuit). Closes the silent Ed25519-only downgrade (EXOCHAIN-REM-005).

Float arithmetic is denied workspace-wide via `#[deny(clippy::float_arithmetic)]`.

## License

Apache-2.0 — See [LICENSE](LICENSE) and [docs/legal/LICENSING-POSITION.md](docs/legal/LICENSING-POSITION.md).

---
*EXOCHAIN Foundation — Judicial Build Governance*
