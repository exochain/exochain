# Developer Onboarding

> **Audience:** An engineer who just `git clone`d `exochain/exochain` and
> wants to know what to do next.
> **Goal:** Get you from nothing to a running local node, a passing test
> suite, your first constitutional adjudication via MCP, and a clear map
> of where everything lives — in about an hour of wall-clock time.

If you want the philosophy first, read
[`constitutional-model.md`](./constitutional-model.md) before this. If you
want the system-level picture, read
[`architecture-overview.md`](./architecture-overview.md). Both are in the
same directory.

---

## 1. Prerequisites

| Tool                | Version           | Why                                                   |
|---------------------|-------------------|-------------------------------------------------------|
| Rust                | 1.85+ stable      | Workspace compiles with the current stable toolchain  |
| `rustup`            | Any recent        | Toolchain management                                  |
| Clang               | Any recent        | Required for crypto-backend compilation (`blake3` SIMD, `ed25519-dalek`) |
| Git                 | 2.30+             | Submodules and sparse checkouts in tooling            |
| Node.js             | 20+ (optional)    | For `command-base/`, `web/`, `packages/exochain-sdk/` |
| Python              | 3.11+ (optional)  | For `tools/codegen/`, `tools/syntaxis/`, `packages/exochain-py/` |
| Disk                | ~2 GB             | Build artefacts under `target/`                       |
| RAM                 | ~8 GB recommended | Release builds of the full workspace                  |
| Platform            | macOS, Linux, WSL2| Cross-platform CI gate runs on `ubuntu-latest`        |

Quick install (assumes you already have a package manager):

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable
rustup toolchain install nightly   # needed for `cargo +nightly fmt`

# Clang (macOS: already present via Xcode Command Line Tools)
xcode-select --install            # macOS
sudo apt-get install -y clang     # Debian / Ubuntu

# Optional: cargo-deny, cargo-audit — used by the release gates.
cargo install cargo-deny cargo-audit
```

Verify:

```bash
rustc --version         # → rustc 1.85.x (or later)
cargo --version
clang --version
```

---

## 2. First hour

### 2.1 Clone and build

```bash
git clone https://github.com/exochain/exochain.git
cd exochain

# Cold build of the full workspace. Expect ~5 minutes on a modern
# laptop. Subsequent incremental builds are seconds.
cargo build --workspace
```

Expected output tail:

```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 52s
```

If this fails with a missing system library, it is almost always
Clang or OpenSSL on Linux:

```bash
sudo apt-get install -y build-essential clang libssl-dev pkg-config
```

### 2.2 Run the tests

```bash
cargo test --workspace
```

Expected output tail:

```
test result: ok. ... passed; 0 failed; 0 ignored; ...
```

The current workspace inventory lists **2,935 tests**. The number grows as new crates land; consult
`governance/traceability_matrix.md` and the `README.md` repo-truth
table for the latest figure. What matters is `0 failed`.

### 2.3 Run the node binary

EXOCHAIN's single binary is `exochain`, produced by the `exo-node`
crate.

```bash
# Release build — needed for reasonable startup time.
cargo build --release -p exo-node

# Status on a fresh install: creates ~/.exochain/ and reports a clean state.
./target/release/exochain status
```

Expected output (shape):

```
exochain v0.x
  data dir: /Users/you/.exochain
  identity: not initialized
  peers:    0
  checkpoint height: 0
```

### 2.4 Start the MCP server

The constitutional MCP server is the canonical interface for AI agents
and tooling.

```bash
./target/release/exochain mcp
```

The server is now reading newline-delimited JSON-RPC on stdin and
writing responses to stdout. All diagnostics go to stderr so stdout
stays a clean channel.

### 2.5 Talk to the MCP server via piped JSON-RPC

In a separate terminal (or as a one-shot pipeline):

```bash
# Pipe a single initialize + tools/list pair into the server.
(
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
) | ./target/release/exochain mcp
```

Expected output includes the server identity (`exochain-mcp`) and a
JSON array under `"tools"` containing ~40 `exochain_*` entries. The
ones you will care about first:

| Tool                             | What it does                                                                      |
|----------------------------------|-----------------------------------------------------------------------------------|
| `exochain_node_status`           | Current node height, peers, identity                                              |
| `exochain_list_invariants`       | Return the 8 invariants                                                           |
| `exochain_list_mcp_rules`        | Return the 6 MCP rules                                                            |
| `exochain_adjudicate_action`     | Run an action through `Kernel::adjudicate`                                        |
| `exochain_create_decision`       | Create a new governance decision on the DAG                                       |
| `exochain_cast_vote`             | Cast a vote on an open decision                                                   |
| `exochain_check_quorum`          | Check whether a decision has an authentic quorum                                  |

A minimal adjudication call (pipe this into `exochain mcp` the same
way):

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exochain_adjudicate_action","arguments":{"actor":"did:exo:alice","action":"read-record","is_self_grant":false,"modifies_kernel":false}}}
```

You should see a `Verdict::Permitted` response. Flip `is_self_grant`
to `true` and observe a `Verdict::Denied` with a `NoSelfGrant`
violation.

---

## 3. The workspace layout

The workspace root is a plain Cargo workspace. The pieces that matter
for first-week work:

### 3.1 The 20 Rust workspace packages in `crates/`

> The README repo-truth table tracks the current package and source-file counts.

| Crate                | One-line purpose                                                                        |
|----------------------|-----------------------------------------------------------------------------------------|
| `exo-core`           | Cryptographic primitives (BLAKE3, Ed25519), HLC, canonical CBOR, DID, `SignerType`      |
| `exo-identity`       | DID lifecycle, key management, Shamir secret sharing, PACE, vault encryption             |
| `exo-consent`        | Bailment lifecycle, consent policies, default-deny gatekeeper                           |
| `exo-authority`      | Authority chains, delegation registry, permission model, Ed25519 link verification      |
| `exo-dag`            | Immutable DAG ledger, Merkle Mountain Range, Sparse Merkle Tree, BFT consensus adapter  |
| `exo-proofs`         | SNARK, STARK, ZKML proof systems, unified verifier                                      |
| `exo-gatekeeper`     | CGR Kernel, 8 invariants, 6 MCP rules, combinator algebra, holons, TEE attestation       |
| `exo-governance`     | Decisions, quorum, challenge, crosscheck, deliberation, conflict, audit, succession     |
| `exo-escalation`     | Sybil detection, triage, 7-stage adjudication, kanban board, feedback loop              |
| `exo-legal`          | Evidence, eDiscovery, attorney-client privilege, DGCL §144 safe-harbor                  |
| `exo-api`            | Public API surface and GraphQL/REST type exports                                        |
| `exo-gateway`        | HTTP gateway (REST + GraphQL), auth, rate limiting, health probes                       |
| `exo-tenant`         | Multi-tenant isolation and tenant lifecycle                                             |
| `exo-messaging`      | Encrypted messaging between DIDs, optional death-trigger delivery                       |
| `exo-consensus`      | BFT-HotStuff derivative, validator rotation, PACE, checkpoint production                |
| `exo-catapult`       | Event ingestion acceleration / batching                                                 |
| `exo-node`           | The `exochain` binary: P2P, BFT, reactor, API, dashboard, CLI, MCP server               |
| `exochain-sdk`       | In-process Rust SDK: ergonomic wrappers for kernel, identity, consent, authority        |
| `exochain-wasm`      | WebAssembly bindings (141 verified bridge exports)                                      |
| `decision-forum`     | Deliberative decision-making forum protocol and voting engine                           |

### 3.2 SDK and bindings in `packages/`

| Package              | Purpose                                                                                       |
|----------------------|-----------------------------------------------------------------------------------------------|
| `packages/exochain-wasm` | WASM + TypeScript bindings for browser / edge runtimes. Wraps `exochain-wasm` crate output. |
| `packages/exochain-sdk`  | TypeScript SDK for server-side Node integrations.                                         |
| `packages/exochain-py`   | Python SDK for data-science and orchestration tooling.                                    |

### 3.3 Governance in `governance/`

| File                                            | Contents                                                                       |
|-------------------------------------------------|--------------------------------------------------------------------------------|
| `traceability_matrix.md`                        | 86 requirements → crate → tests → status                                       |
| `threat_matrix.md`                              | 14 threats, status, mitigation mapping                                         |
| `quality_gates.md`                              | The 8 pull-request gates and release gates                                     |
| `resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md` | Council resolution defining AEGIS, SYBIL, authentic plurality, work orders |
| `sub_agents.md`                                 | 11 sub-agent charters                                                          |
| `EXOCHAIN-REFACTOR-PLAN.md`                     | Active refactor roadmap                                                        |

### 3.4 Tools in `tools/`

| Tool              | What it does                                                                                 |
|-------------------|----------------------------------------------------------------------------------------------|
| `tools/codegen/`         | `generate_crate.py` — scaffolds a new workspace crate with all the required boilerplate |
| `tools/syntaxis/`        | Node registry + workflow code generator (maps 23 visual node types to Rust combinators) |
| `tools/cross-impl-test/` | Rust vs JavaScript hash-compatibility test harness (release gate)                        |
| `tools/sybil-cli/`       | Operator CLI for Sybil detection, triage, and adjudication                               |
| `tools/repo_truth.sh`    | Regenerates the `README.md` repo-status table from source                                |

### 3.5 Other top-level directories

| Directory         | Purpose                                                                |
|-------------------|------------------------------------------------------------------------|
| `docs/`           | Architecture, guides, ADRs, reference, council panel reports           |
| `command-base/`   | CommandBase.ai operational hypervisor (Node/Express + SQLite)          |
| `exoforge/`       | Governance triage, implementation planning, validation, and monitoring tools |
| `web/`            | Decision Forum React UI                                                |
| `demo/`           | Standalone demo stack (Node microservices + React + Postgres)          |
| `tla/`            | TLA+ specifications for core protocols                                 |
| `deploy/`         | Deployment manifests (Docker Compose, Fly.io, Railway)                 |

---

## 4. Code style and constraints

The full list lives in [`../../AGENTS.md`](../../AGENTS.md). The
short list you need before writing your first line of code:

### 4.1 Absolute determinism

- **No floating-point arithmetic.** The workspace sets
  `#[deny(clippy::float_arithmetic)]`. Use integers or basis points
  (1/10000). No `f32`, no `f64`.
- **BTreeMap, not HashMap.** `HashMap` iteration order is
  non-deterministic and will break hashing and DAG reproducibility.
  Use `std::collections::BTreeMap` and `BTreeSet`, or the
  `DeterministicMap` alias from `exo_core`.
- **Canonical CBOR for hashed data.** Use `ciborium` with sorted
  keys, never JSON. JSON key ordering is not guaranteed across
  implementations.
- **No `std::time::SystemTime::now()` or `Instant::now()` in
  governance logic.** Use the Hybrid Logical Clock in `exo_core::hlc`.
- **No randomness in logic.** Randomness is permitted only for key
  generation (`ed25519-dalek` keypairs).

### 4.2 No `unsafe`

- `unsafe_code = "deny"` at the workspace level.
- No `unsafe` blocks, `unsafe impl`, or `unsafe fn`.

### 4.3 Error handling

- Define errors with `thiserror`. Every crate has an `error.rs`.
- Return `Result<T, CrateError>`. Avoid `unwrap()` and `expect()` in
  non-test code — Clippy sets both to `warn`.
- Every error variant must carry enough context to diagnose the
  failure without a debugger.

### 4.4 Address the 8 invariants where applicable

If you are adding a new action, a new event type, or a new code path
that consumes `AdjudicationContext`, ask: which of the 8 invariants
apply, and which are definitely not applicable? Document the answer in
the module doc-comment. See
[`constitutional-model.md`](./constitutional-model.md) for the
invariants themselves and
[`../../AGENTS.md`](../../AGENTS.md) — "How to Add a New Invariant" for
the amendment process.

---

## 5. Running a local dev node

The single-node path, suitable for development and integration tests:

```bash
# One-time init. Creates ~/.exochain/ with a freshly generated DID,
# Ed25519 keypair, and validator manifest.
./target/release/exochain init

# Start the node as a single validator. No peers, no discovery.
# API: http://localhost:3000
# Dashboard: http://localhost:3000 (served by the same port)
./target/release/exochain start --validator
```

What you get on port 3000:

| Path                   | What it serves                                                                  |
|------------------------|---------------------------------------------------------------------------------|
| `GET /`                | Live dashboard (HTML)                                                           |
| `GET /health`          | Liveness probe                                                                  |
| `GET /ready`           | Readiness probe                                                                 |
| `GET /api/status`      | Node height, peers, checkpoint, validator set                                   |
| `POST /api/decisions`  | Create a governance decision                                                    |
| `POST /api/votes`      | Cast a vote                                                                     |
| `GET /api/checkpoints/:id` | Retrieve a checkpoint by ID                                                 |
| `GET /metrics`         | Prometheus exposition                                                           |

### 5.1 Check consensus status

```bash
curl -s http://localhost:3000/api/status | jq .
```

Expected shape (single-node):

```json
{
  "height":         12,
  "validator_set": ["did:exo:local-dev"],
  "peers":          0,
  "last_checkpoint":"0xabcd…",
  "consensus":      "steady",
  "kernel_hash":    "blake3:…"
}
```

When running a multi-node cluster via `docker-compose.multinode.yml`,
the same endpoint on any node will show the full validator set and
the current HotStuff view number.

---

## 6. Making your first change

### 6.1 Pick an issue

Three sources, in priority order:

1. `GAP-REGISTRY.md` — the tracked gap list, ordered by priority. Good
   for scoped work that lands on a known deadline.
2. GitHub Issues with the label `good-first-issue` — intentionally
   scoped for new contributors.
3. GitHub Issues with the label `exoforge:triage` — items that have
   been triaged by ExoForge and include a council review. These tend
   to have the clearest acceptance criteria.

### 6.2 The CI quality gates

Every PR runs the `.github/workflows/ci.yml` pipeline. It currently defines 20
numbered gates plus the required "All Constitutional Gates" aggregator. The
gates cover build, debug/release tests, coverage, clippy, format, audit, deny,
docs, repo hygiene, SBOM dry-run, unused dependency checks, gateway/DB/consensus
integration, state sync, cross-platform builds, 0dentity coverage, WASM build,
bridge verification, and WASM/JS export sync.

See [`../../governance/quality_gates.md`](../../governance/quality_gates.md)
for the authoritative list.

### 6.3 Run the gates locally before you push

```bash
# The "close to CI" command — run these four before every PR.
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Nightly is needed for fmt --check on the full codebase.
cargo +nightly fmt --all -- --check

# If you changed dependencies.
cargo deny check
cargo audit
```

If you want to reproduce the CI environment more faithfully:

```bash
docker-compose -f docker-compose.ci.yml up --abort-on-container-exit
```

### 6.4 Commit conventions

EXOCHAIN uses conventional commits. The release gate
(`CHANGELOG.md` check) requires them.

```
feat(exo-gatekeeper): add invariant 9 for evidence-bundle integrity
fix(exo-dag): correct MMR leaf hashing for odd-length inputs
docs(guides): add developer-onboarding.md
chore: bump rust-toolchain to 1.85.0
refactor(exo-consent): extract bailment state machine
test(exo-governance): pin CR-001 §8.3 synthetic-vote exclusion
```

Scopes follow the crate names. `docs`, `chore`, `refactor`, `test`,
and `feat` / `fix` are the common prefixes.

### 6.5 The council assessment process for constitutional changes

If your change touches any of the following, it is constitutional and
needs a resolution in `governance/resolutions/`:

- The 8 invariants or the `InvariantSet`.
- The 6 MCP rules or the `SignerType` binding.
- The kernel binary (`Kernel::new`, `Kernel::adjudicate`, the
  constitution hash).
- Separation-of-powers enforcement (`GovernmentBranch`).
- Quorum computation, including the synthetic-voice exclusion rule.

The process, summarised from [`../../AGENTS.md`](../../AGENTS.md) and
CR-001:

1. Draft a resolution under `governance/resolutions/CR-00N-…md`.
2. Address: which invariants change, how determinism is preserved,
   what new attack vectors are introduced, how separation of powers
   is affected, whether consent requirements change.
3. Run the full quality-gate suite locally (above).
4. Run `tools/cross-impl-test/compare.sh`.
5. Open a PR with the resolution + code change. Tag the council
   panels listed in `docs/council/`.
6. CI re-runs the gates and the cross-impl test. PR cannot merge
   until all pass.
7. For amendment-gated changes (see
   [`constitutional-model.md`](./constitutional-model.md) §6), the
   additional formal-proof and external-audit steps apply.

---

## 7. Governance artefacts

| Artifact                                                | What it is                                              |
|---------------------------------------------------------|---------------------------------------------------------|
| [`../../governance/traceability_matrix.md`](../../governance/traceability_matrix.md) | 86 requirements, each mapped to crate/module/tests/status |
| [`../../governance/threat_matrix.md`](../../governance/threat_matrix.md) | 14 threats with mitigation references                    |
| [`../../governance/quality_gates.md`](../../governance/quality_gates.md) | The 20 numbered CI gates plus required aggregator         |
| [`../../governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md`](../../governance/resolutions/CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY.md) | The AEGIS / SYBIL resolution (draft, pending ratification) |
| [`../../governance/sub_agents.md`](../../governance/sub_agents.md) | 11 sub-agent charters with ownership boundaries          |
| [`../../governance/EXOCHAIN-REFACTOR-PLAN.md`](../../governance/EXOCHAIN-REFACTOR-PLAN.md) | Active refactor roadmap                                  |

When in doubt about whether a change is in scope, start from the
traceability matrix — find the row that your change touches, and
confirm the status and the test locations agree with what you are
about to write.

---

## 8. Where to get help

| You want...                                          | Read                                                                                      |
|------------------------------------------------------|-------------------------------------------------------------------------------------------|
| The philosophical and formal model                    | [`constitutional-model.md`](./constitutional-model.md)                                    |
| A layered architecture map                            | [`architecture-overview.md`](./architecture-overview.md)                                  |
| A pre-existing deep dive on layer structure           | [`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)                      |
| The guide for AI agents connecting to EXOCHAIN        | [`ai-agent-guide.md`](./ai-agent-guide.md)                                                |
| AI development constraints (determinism, no-unsafe…)  | [`../../AGENTS.md`](../../AGENTS.md)                                                      |
| How the CGR Kernel is used from user code             | [`cgr-developer-guide.md`](./cgr-developer-guide.md)                                      |
| How to stand up a production deployment               | [`production-deployment.md`](./production-deployment.md), [`DEPLOYMENT.md`](./DEPLOYMENT.md) |
| How to integrate with ExoForge                        | [`ARCHON-INTEGRATION.md`](./ARCHON-INTEGRATION.md)                                        |
| How to report a security issue                        | [`../../SECURITY.md`](../../SECURITY.md)                                                  |
| How to get non-security support                       | [`../../SUPPORT.md`](../../SUPPORT.md)                                                    |
| How to contribute a PR                                | [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)                                          |
| The formal threat model                               | [`../architecture/THREAT-MODEL.md`](../architecture/THREAT-MODEL.md)                      |
| A quick list of all crates and their APIs             | [`../reference/CRATE-REFERENCE.md`](../reference/CRATE-REFERENCE.md)                      |

For live help:

- Open an issue on GitHub with the `question` label.
- For security issues, do not open a public issue — follow the
  process in [`../../SECURITY.md`](../../SECURITY.md).
- For governance questions, tag the appropriate council panel from
  `docs/council/`.

---

## 9. A one-hour checklist

If you want a tight sequence to follow, here it is:

- [ ] `git clone git@github.com:exochain/exochain.git && cd exochain`
- [ ] `cargo build --workspace` (5 min)
- [ ] `cargo test --workspace` (2 min; expect 0 failures)
- [ ] `cargo build --release -p exo-node` (3 min)
- [ ] `./target/release/exochain status` — confirm data dir creation
- [ ] `./target/release/exochain init`
- [ ] `./target/release/exochain start --validator` (separate shell)
- [ ] `curl -s http://localhost:3000/api/status | jq .`
- [ ] `./target/release/exochain mcp` (separate shell)
- [ ] Pipe the two JSON-RPC requests from §2.5 and verify the
      response tools list
- [ ] Pipe the `exochain_adjudicate_action` call from §2.5 and
      observe `Permitted`
- [ ] Flip `is_self_grant: true` and observe `Denied` with
      `NoSelfGrant`
- [ ] Open [`constitutional-model.md`](./constitutional-model.md) and
      read §3 (the 8 invariants)
- [ ] Pick an issue from `GAP-REGISTRY.md` or the `good-first-issue`
      GitHub label
- [ ] Run the four pull-request gate commands from §6.3 before
      pushing

You are now oriented.

---

Copyright (c) 2025–2026 EXOCHAIN Foundation. Licensed under the
Apache License, Version 2.0. See
[`../../LICENSE`](../../LICENSE).
