# AGENTS.md — AI Development Instructions for EXOCHAIN

This document provides instructions for AI agents (Claude, Codex, Copilot, or any
LLM-based development tool) working on the EXOCHAIN constitutional trust fabric.

EXOCHAIN is a Rust workspace implementing a governance runtime where every operation
is constitutionally adjudicated. The system enforces separation of powers, consent-based
authority, and cryptographic provenance for all actions.

## Constitutional Constraints

These constraints are non-negotiable. Every change must satisfy all of them.

### 1. Absolute Determinism

The same input must always produce the same output, across runs, platforms, and time.

- **No floating-point arithmetic.** The workspace denies `clippy::float_arithmetic`,
  `clippy::float_cmp`, and `clippy::float_cmp_const`. Use integer arithmetic or
  fixed-point representations. If you need fractional values, use basis points (1/10000)
  or millibels.
- **BTreeMap only.** Never use `HashMap` or `HashSet`. These have non-deterministic
  iteration order. Use `BTreeMap` and `BTreeSet` from `std::collections`, or the
  `DeterministicMap` alias from `exo-core`.
- **Canonical serialization.** All data that gets hashed must be serialized via CBOR
  using the `ciborium` crate with sorted keys. Never hash JSON directly since key
  ordering is not guaranteed.
- **No system time.** Use the Hybrid Logical Clock (HLC) from `exo_core::hlc` for
  all timestamps. Never call `std::time::SystemTime::now()` or `Instant::now()` in
  production code.
- **No randomness in logic.** Randomness is only permitted for key generation
  (`ed25519-dalek` key pairs). All governance logic must be purely deterministic.

### 2. No Unsafe Code

The workspace sets `unsafe_code = "deny"`. Do not use `unsafe` blocks, `unsafe impl`,
or `unsafe fn`. If you believe unsafe is required, document the justification and
request a constitutional amendment through the governance process.

### 3. Error Handling

- Use `thiserror` for error type definitions. Every crate has an error module.
- Prefer `Result<T, CrateError>` return types. Avoid `unwrap()` and `expect()` in
  non-test code (both are set to `warn` level).
- Every error variant must carry enough context to diagnose the failure without
  access to the source code.

### 4. The Eight Constitutional Invariants

Every action in the system must satisfy these invariants, enforced by the kernel
in `exo-gatekeeper`:

1. **SeparationOfPowers** — No single actor may hold legislative + executive + judicial power.
2. **ConsentRequired** — Action denied without active bailment consent.
3. **NoSelfGrant** — An actor cannot expand its own permissions.
4. **HumanOverride** — Emergency human intervention must always be possible.
5. **KernelImmutability** — Kernel configuration cannot be modified after creation.
6. **AuthorityChainValid** — Authority chain must be valid and unbroken.
7. **QuorumLegitimate** — Quorum decisions must meet threshold requirements.
8. **ProvenanceVerifiable** — All actions must have verifiable provenance.

## Workspace Architecture

```
crates/
  exo-core/          Foundational types: HLC, crypto, BCTS, DID, Hash256
  exo-identity/      DID management, identity verification
  exo-consent/       Bailment consent engine (BCTS state machine)
  exo-authority/     Authority delegation, permission chains
  exo-gatekeeper/    Kernel, invariants, combinator algebra, holons, MCP, TEE
  exo-governance/    Legislative branch: proposals, voting, quorum
  exo-escalation/    Escalation paths, human override
  exo-legal/         Legal compliance, jurisdictional rules
  exo-dag/           Immutable causal DAG ledger
  exo-proofs/        Cryptographic proof generation and verification
  exo-api/           External API surface
  exo-gateway/       Gateway routing, rate limiting
  exo-tenant/        Multi-tenant isolation
  decision-forum/    Deliberative decision-making forum

governance/          Constitutional documents and council assessments
tools/
  codegen/           Crate scaffolding generator
  syntaxis/          Node registry and workflow code generator
  cross-impl-test/   Cross-implementation consistency testing
```

### Dependency Order

`exo-core` is the root. All crates depend on it. The dependency graph flows:

```
exo-core
  -> exo-identity, exo-consent, exo-authority, exo-dag, exo-proofs
    -> exo-gatekeeper (depends on most of the above)
      -> exo-governance, exo-escalation, exo-legal
        -> exo-tenant, exo-api, exo-gateway
          -> decision-forum
```

## Core vs Adjacent Surface Rules

Core is core. Adjacent products, demos, customer-zero apps, portfolio sites, and
integration scaffolds are not automatically part of the EXOCHAIN constitutional
trust fabric just because they live near it or reference it.

### Core-First Operating Rule

AI coding agents must protect the canonical Rust trust fabric before expanding,
polishing, or hardening adjacent surfaces. When an external report mixes EXOCHAIN
with CommandBase, crosschecked.ai, livesafe.ai, demos, archives, or generated
applications, split the corpus into independently triaged records before editing.
Do not allow the urgency of an adjacent surface to obscure a live core issue, and
do not let adjacent code expand the trusted computing base by proximity.

### Required Classification

Before triage, planning, coding, or remediation, classify every finding and every
changed path as exactly one of:

- **EXOCHAIN core** — Rust workspace crates, governance/runtime logic, canonical
  cryptography, DAG, consent, authority, gatekeeper, node, gateway, SDK, WASM,
  proofs, tenant, messaging, CI gates, and constitutional governance artifacts.
- **Core runtime adapter** — code that directly exposes or transports core
  invariants across APIs, MCP, WASM, P2P, persistence, or deployment.
- **Adjacent surface** — CommandBase, crosschecked.ai, livesafe.ai, customer-zero
  apps, websites, demos, dashboards, generated prototypes, or product shells that
  are not themselves the canonical Rust trust fabric.
- **Imported evidence** — external HTML reports, zip files, screenshots, logs,
  generated scans, or consultant readouts. These are inputs for verification, not
  source-of-truth code.
- **Third-party/vendor** — vendored packages, generated dependency trees, build
  artifacts, archives, or upstream code not owned by EXOCHAIN.

If a path cannot be classified quickly, stop and classify it before editing. Do
not blend core and adjacent remediation in one commit unless the adjacent code is
the actual runtime adapter proving access to core enforcement.

### Adjacent Surface Intake Gate

Do not add, import, or materially modify an adjacent surface until the change
includes a concise intake record in the relevant PR description, plan, or
surface-owned documentation. The intake record must state:

- owner and accountable maintainer;
- deployment status (`prototype`, `internal`, `customer-zero`, or `production`);
- whether the surface is allowed to make EXOCHAIN constitutional trust claims;
- whether the surface can read or write EXOCHAIN core state, signatures,
  credentials, governance outcomes, consent records, or provenance records;
- exact trust boundary between the adjacent surface and EXOCHAIN core;
- surface-specific test command and CI gate;
- secrets inventory and runtime configuration source;
- rollback or disablement path if the surface leaks, misroutes, or misstates
  core trust decisions.

If the intake record cannot be completed, quarantine the surface as adjacent and
do not wire it into core runtime paths.

### Remediation Priority

1. Live, reproducible EXOCHAIN core vulnerabilities come first.
2. Core runtime adapters come second when they expose core state, signatures,
   credentials, governance outcomes, or external write paths.
3. Adjacent surfaces come after core unless they are already deployed as the
   production entrypoint for core trust decisions.
4. Documentation and portfolio cleanup follow verified code remediation.

Do not claim an adjacent fix remediates a core vulnerability. Do not claim a core
invariant protects an adjacent app unless the app calls the relevant core API and
has tests proving the enforcement boundary.

### No Trust Claim By Proximity

Marketing copy, screenshots, diagrams, generated prototypes, local demos, and
portfolio pages do not prove constitutional enforcement. An adjacent surface may
claim EXOCHAIN protection only when:

- the runtime path invokes the relevant EXOCHAIN core API or verified adapter;
- tests prove fail-closed behavior when the core API rejects, times out, or is
  unavailable;
- the surface cannot mint, cache, or simulate consent, authority, provenance, or
  governance outcomes outside core enforcement;
- status, health, debug, telemetry, and error responses cannot disclose
  bootstrap tokens, private keys, raw secrets, authority chains, or tenant data.

If these conditions are not proven, describe the surface as unaudited adjacent
code and do not imply constitutional guarantees.

### External Findings

External reports from auditors, consultants, scanners, or AI systems are
hypotheses. For each reported concern:

1. Reproduce against current `main` or the branch under review, because reports
   may be stale.
2. Locate the actual owned file and runtime path. If the file is generated,
   archived, imported evidence, or third-party code, record that disposition.
3. Write a failing regression test or deterministic source guard before changing
   production code.
4. Fix the smallest owned enforcement boundary that blocks the exploit class.
5. Re-run focused tests, touched-crate tests, relevant workspace gates, and a
   bypass search for sibling ingress paths.
6. Commit core remediations separately from adjacent-surface hardening.

Imported evidence must remain read-only. Do not commit external HTML reports,
zip archives, screenshots, generated scanner output, or consultant artifacts as
source files. Extract the actionable claim, affected owned path, reproduction
status, disposition, and validation command into a triage record or remediation
plan.

### Adding Adjacent Surfaces

Any new adjacent product or surface, including CommandBase, crosschecked.ai,
livesafe.ai, or future portfolio apps, must include an explicit ownership and
trust-boundary statement before code lands:

- owner and release status (`prototype`, `internal`, `customer-zero`, or
  `production`);
- whether it is allowed to make constitutional trust claims;
- which EXOCHAIN core APIs it calls, if any;
- threat model for secrets, identity, consent, authority, provenance, and
  external writes;
- test command and CI gate for that surface;
- deployment boundary and credentials model.

Adjacent surfaces must fail closed on missing secrets, must not expose bootstrap
tokens or private key material through health/status/debug endpoints, must not
ship hardcoded production credentials, and must not use development fallbacks in
production code paths.

### Core Regression Firewall

Every adjacent-surface PR must prove that it did not alter EXOCHAIN core behavior
unless the change is explicitly classified as a core runtime adapter. The PR must
include:

- a path classification list for every touched file;
- a statement of whether any `crates/`, `packages/exochain-wasm/`,
  `governance/`, `tools/`, CI, or deployment contract changed;
- focused tests for the adjacent surface and any adapter boundary it calls;
- the normal core gates when core, adapter, CI, governance, or deployment files
  changed;
- a bypass search for sibling ingress paths when the surface accepts credentials,
  signatures, consent, governance actions, tenant identifiers, webhooks, or
  external writes.

Adjacent surfaces must not share core bootstrap keys, production signing keys,
tenant secrets, or emergency override credentials. Use separate secret scopes and
fail closed if any required secret is absent or malformed.

### Commit and PR Isolation

Use separate commits and preferably separate PRs for:

- EXOCHAIN core vulnerability remediation;
- core runtime adapter hardening;
- adjacent-surface hardening;
- imported-evidence triage;
- documentation, portfolio, or agent-rule updates.

Only combine these categories when the code cannot be validated independently.
If combined, the PR description must explain why and list the exact tests proving
both the core invariant and the adjacent boundary.

## How to Add a New Crate

Use the scaffolding generator:

```bash
python3 tools/codegen/generate_crate.py exo-newcrate module1 module2 module3
```

This generates the full crate skeleton with:
- `Cargo.toml` linked to workspace dependencies
- `src/lib.rs` with module declarations
- `src/error.rs` with typed error variants
- `src/<module>.rs` with struct, trait, and test skeleton
- `tests/<module>_tests.rs` integration tests

The generator also adds the crate to the workspace `Cargo.toml` members list.

After generation:

1. Verify the crate builds: `cargo build -p exo-newcrate`
2. Verify tests pass: `cargo test -p exo-newcrate`
3. Add the crate to the dependency graph in the appropriate position
4. Customize the generated types for your domain
5. Ensure all eight invariants are addressed where applicable

## How to Add a New Invariant

Invariants live in `exo-gatekeeper`. To add a ninth invariant:

1. Add the variant to `ConstitutionalInvariant` in `crates/exo-gatekeeper/src/invariants.rs`:
   ```rust
   pub enum ConstitutionalInvariant {
       // ... existing variants ...
       NewInvariantName,
   }
   ```

2. Add it to `InvariantSet::all()` so it is enforced by default.

3. Implement the check logic in `InvariantEngine::check()` in the same file.
   The check receives an `InvariantContext` with actor info, consent state,
   authority chain, etc.

4. Add the invariant to the kernel's adjudication loop in
   `crates/exo-gatekeeper/src/kernel.rs`.

5. Write tests proving the invariant:
   - Holds for valid operations
   - Rejects for violating operations
   - Cannot be bypassed by any combination of actor roles
   - Produces a detailed `InvariantViolation` with evidence

6. Update `tools/syntaxis/node_registry.json` to reference the new invariant
   in all node types it applies to.

7. Submit a governance proposal (see below) documenting the new invariant's
   constitutional basis and rationale.

## How to Run the Council Assessment Process

The council assessment evaluates whether a change satisfies all constitutional
requirements. Assessments are stored in `governance/`.

### Running an assessment:

1. Document the proposed change in a resolution file under `governance/resolutions/`.

2. The resolution must address:
   - Which constitutional invariants are affected
   - How determinism is preserved
   - What new attack vectors are introduced (if any)
   - How the change interacts with separation of powers
   - Whether consent requirements change

3. Run the full quality gate check locally:
   ```bash
   cargo build --workspace --release
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   cargo doc --workspace --no-deps
   ```

4. Run the cross-implementation consistency test:
   ```bash
   ./tools/cross-impl-test/compare.sh
   ```

5. If all gates pass, the resolution can be submitted as a PR. The CI pipeline
   enforces the same gates automatically.

## How to Use Syntaxis to Compose Governance Pipelines

Syntaxis is the visual-to-code bridge. The node registry
(`tools/syntaxis/node_registry.json`) maps 23 visual builder node types to
concrete Rust implementations.

### Creating a workflow:

1. Define the workflow as JSON:
   ```json
   {
       "name": "consent-gated-action",
       "description": "Verify identity, check consent, then adjudicate",
       "steps": [
           { "node": "identity-verify", "id": "verify_id" },
           { "node": "consent-verify", "id": "check_consent" },
           { "node": "kernel-adjudicate", "id": "adjudicate" }
       ],
       "composition": "sequence",
       "error_strategy": "fail_fast"
   }
   ```

2. Generate the Rust code:
   ```bash
   python3 tools/syntaxis/generate_workflow.py workflow.json --output-dir generated/
   ```

3. This produces:
   - A Rust module with the combinator chain
   - Test scaffolding verifying determinism
   - Integration glue for the gatekeeper engine

4. Copy the generated module into the appropriate crate and add it to `lib.rs`.

### Composition types:

| Type | Combinator | Behavior |
|------|-----------|----------|
| `sequence` | `Sequence([...])` | Execute in order, threading output to input |
| `parallel` | `Parallel([...])` | Execute independently, merge all outputs |
| `choice` | `Choice([...])` | Try in order, first success wins |
| `guarded_sequence` | Nested `Guard` | Each step guards the next |

### The combinator algebra:

Every governance operation reduces to a combinator expression. Reduction is pure:

```
reduce(combinator, input) -> Result<output, error>
```

Available terms: `Identity`, `Sequence`, `Parallel`, `Choice`, `Guard`,
`Transform`, `Retry`, `Timeout`, `Checkpoint`.

The kernel reduces the combinator and checks all applicable invariants before
and after reduction. If any invariant fails, the entire operation is rejected
with a detailed violation report.

## CI and Quality Gates

The GitHub Actions pipeline (`.github/workflows/ci.yml`) enforces CR-001
Section 8.8 quality gates. All must pass:

1. **Build** — `cargo build --workspace --release`
2. **Test** — `cargo test --workspace` (debug and release)
3. **Coverage** — cargo-tarpaulin, minimum 90% line coverage
4. **Lint** — `cargo clippy --workspace -- -D warnings`
5. **Format** — `cargo fmt --all -- --check`
6. **Audit** — `cargo audit` (no known vulnerabilities)
7. **Deny** — `cargo deny check` (license and advisory compliance)
8. **Doc** — `cargo doc --workspace --no-deps` (no warnings)

Run all gates locally before pushing:

```bash
cargo build --workspace --release && \
cargo test --workspace && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo fmt --all -- --check && \
cargo doc --workspace --no-deps
```

## Common Patterns

### Creating a new type

```rust
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MyType {
    pub id: String,
    pub created_at: exo_core::Timestamp,
    pub data: BTreeMap<String, String>,  // Never HashMap
}
```

### Returning errors

```rust
use crate::error::MyCrateError;

pub fn do_thing(input: &str) -> Result<Output, MyCrateError> {
    if input.is_empty() {
        return Err(MyCrateError::ValidationError {
            reason: "input must not be empty".into(),
        });
    }
    // ...
    Ok(output)
}
```

### Writing determinism tests

```rust
#[test]
fn test_determinism() {
    let input = make_input();
    let result1 = process(&input);
    let result2 = process(&input);
    assert_eq!(result1, result2, "same input must produce same output");
}
```

### Using the combinator algebra

```rust
use exo_gatekeeper::combinator::*;

let workflow = Combinator::Sequence(vec![
    Combinator::Guard(
        Box::new(Combinator::Identity),
        Predicate {
            name: "auth_check".into(),
            required_key: "authorized".into(),
            expected_value: None,
        },
    ),
    Combinator::Transform(
        Box::new(Combinator::Identity),
        TransformFn {
            name: "stamp".into(),
            output_key: "processed".into(),
            output_value: "true".into(),
        },
    ),
]);

let input = CombinatorInput::new().with("authorized", "yes");
let output = reduce(&workflow, &input).expect("reduction");
assert_eq!(output.fields.get("processed").unwrap(), "true");
```

## What Not to Do

- Do not stub, shortcut, skip, postpone, leave `TODO`, or create "future phase"
  placeholders in production or remediation work.
- Do not remediate a report without first confirming the issue still exists in
  current code.
- Do not treat imported reports, zip files, generated artifacts, or third-party
  source as owned EXOCHAIN code without classification.
- Do not let adjacent surfaces claim constitutional enforcement without a tested
  call path into EXOCHAIN core.
- Do not use `HashMap` or `HashSet` anywhere.
- Do not use floating-point numbers (`f32`, `f64`) anywhere.
- Do not call `std::time::SystemTime::now()` or `Instant::now()`.
- Do not use `unsafe`.
- Do not use `unwrap()` or `expect()` outside of tests.
- Do not add dependencies without checking `deny.toml` license compliance.
- Do not modify the kernel after initialization (KernelImmutability invariant).
- Do not grant permissions to the requesting actor (NoSelfGrant invariant).
- Do not bypass consent checks (ConsentRequired invariant).
- Do not remove human override capability (HumanOverride invariant).
