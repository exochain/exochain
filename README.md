# EXOCHAIN v2.2

> **Trust Fabric for the Digital Economy**
>
> *Spec Revision 2.2 — Green-Field Implementation*

EXOCHAIN is a verifiable, privacy-preserving substrate enabling secure identity adjudication, data sovereignty, and deterministic finality. Built in Rust with absolute determinism, constitutional governance, and post-quantum readiness.

## Repo Status

> Run `bash tools/repo_truth.sh` to regenerate these numbers from source.

| Metric | Value | Source |
|--------|-------|--------|
| Rust crates | 15 | `ls -d crates/*/` |
| Rust source files | 148 | `find crates -name '*.rs'` |
| Rust LOC | ~31,000 | `wc -l` |
| Library tests | 1,116 passing, 0 failing | `cargo test --workspace --lib` |
| CI quality gates | 9 | `.github/workflows/ci.yml` |
| Published releases | None (pre-release) | `git tag -l` |
| License | Apache-2.0 | `LICENSE`, `Cargo.toml` |

### What is verified today

- **1,116 library tests pass** with zero failures (`cargo test --workspace --lib`)
- **Build succeeds** for all library crates, binaries, tests, and benchmarks
- **Clippy clean** under `-D warnings` for production code
- **Format clean** under `cargo +nightly fmt --all -- --check`
- **9 CI quality gates** defined and enforced (build, test, coverage, lint, format, audit, deny, doc, hygiene)
- **Traceability matrix** maps 80 requirements: 76 implemented, 2 partial, 2 planned
- **Threat model** covers 17 threats tracked: 16 mitigated, 1 partial (T-17 post-quantum ML-DSA), 0 planned — see `governance/threat_matrix.md`
- **Constitutional invariants** enforced via the CGR kernel in all governance paths
- **No floating-point arithmetic** — denied workspace-wide via `#[deny(clippy::float_arithmetic)]`

### What is supported by design but not yet production-hardened

- **90% coverage threshold** — configured in CI via cargo-tarpaulin; not independently verified outside CI
- **exo-gateway binary** — library compiles and tests pass; binary is a placeholder (HTTP server runtime not yet integrated)
- **GraphQL API** — types and schema stubs exist in `exo-api`; async runtime integration pending
- **exo-dag benchmark** — disabled; needs rewrite against current API
- **Post-quantum signatures** — `Signature` enum supports Ed25519/PostQuantum/Hybrid; PQ implementation is stub-level

### Roadmap / Planned

- First versioned release (see `.github/workflows/release.yml` for the dry-run workflow)
- SBOM generation and supply-chain attestation
- Production HTTP server in `exo-gateway` (currently served via Node.js demo)
- Continuous governance monitoring via ExoForge
- National AI Policy Framework compliance extensions

## The Five Axioms

1. **Identity Adjudication** — Decentralized identity with cryptographic proof, not administrative fiat.
2. **Data Sovereignty** — Data belongs to its subject; consent is explicit, revocable, and auditable.
3. **Deterministic Finality** — Every operation is reproducible and verifiable; no floating-point arithmetic permitted.
4. **Constitutional Governance** — All system behavior is governed by ratified resolutions (CR-001 AEGIS/SYBIL framework).
5. **Authentic Plurality** — Sybil-resistant participation ensuring one-entity-one-voice integrity.

## Repository Structure

### Core Crates (15)

| Crate | Description |
|-------|-------------|
| `exo-core` | Cryptographic primitives (BLAKE3, Ed25519, post-quantum), Canonical CBOR, HLC |
| `exo-governance` | Constitutional governance engine, AEGIS framework, council process |
| `exo-gatekeeper` | TEE/Enclave interfaces, attestation verification, kernel invariants, holon, MCP |
| `exo-dag` | Directed Acyclic Graph engine, BFT consensus adapter, checkpointing, HLC |
| `exo-gateway` | External gateway interfaces and API routing (library; binary is placeholder) |
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

### Governance & Infrastructure

* **`governance/`** — Council resolutions, sub-agent charters, traceability matrices, quality gates
* **`docs/`** — Architecture, guides, council panel reports, proofs, reference documentation
* **`.github/workflows/`** — CI pipeline (9 quality gates), release workflow, ExoForge triage

## Governance & Compliance

This repository is managed under strict **Judicial Build Governance**. All contributions must align with `EXOCHAIN_Specification_v2.2.pdf`. CR-001 (AEGIS/SYBIL/Authentic Plurality) is **RATIFIED**.

### Key Governance Artifacts

* [Traceability Matrix](governance/traceability_matrix.md) — 76 implemented, 2 partial, 2 planned
* [Threat Model](governance/threat_matrix.md) — 15 mitigated, 2 partial, 2 planned
* [Quality Gates](governance/quality_gates.md) — 8 CI-enforced gates
* [Sub-Agent Charters](governance/sub_agents.md) — 11 agent charters documented
* [Council Resolutions](governance/resolutions/INDEX.md) — CR-001 RATIFIED
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

## ExoForge (Autonomous Implementation Engine)

[ExoForge](https://github.com/exochain/exoforge) is the autonomous implementation engine that establishes a **perpetual self-improvement cycle** for ExoChain:

```
Widget AI Help → Feedback Ingestion → Triage → AI-IRB Council Review → Implementation → Constitutional Validation → PR → Deploy
```

- **7 Archon commands** — Triage, council review, Syntaxis generation, PRD generation, implementation, bug fixing, constitutional validation
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

# Run all library tests
cargo test --workspace --lib

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
* **PostQuantum** — Forward-looking post-quantum signature scheme (stub-level)
* **Hybrid** — Combined Ed25519 + post-quantum for transition period (stub-level)

Float arithmetic is denied workspace-wide via `#[deny(clippy::float_arithmetic)]`.

## License

Apache-2.0 — See [LICENSE](LICENSE) and [docs/legal/LICENSING-POSITION.md](docs/legal/LICENSING-POSITION.md).

---
*EXOCHAIN Foundation — Judicial Build Governance*
