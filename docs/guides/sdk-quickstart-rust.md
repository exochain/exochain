---
title: "Rust SDK Quickstart"
status: active
created: 2026-04-15
tags: [exochain, sdk, rust, quickstart, guide]
---
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


# Rust SDK Quickstart

**Get productive with the `exochain-sdk` crate in ten minutes.**

The Rust SDK (`exochain-sdk`) is the canonical, deterministic reference implementation of the EXOCHAIN constitutional governance fabric. Every primitive here — DIDs, bailments, decisions, authority chains, kernel verdicts — is bit-for-bit reproducible across platforms.

---

## Table of Contents

- [Why EXOCHAIN](#why-exochain)
- [Installation](#installation)
- [The prelude](#the-prelude)
- [Domain 1: Identity](#domain-1-identity)
- [Domain 2: Consent (bailments)](#domain-2-consent-bailments)
- [Domain 3: Governance (decisions + voting)](#domain-3-governance-decisions--voting)
- [Domain 4: Authority chains](#domain-4-authority-chains)
- [Domain 5: Crypto primitives](#domain-5-crypto-primitives)
- [Domain 6: Constitutional kernel](#domain-6-constitutional-kernel)
- [Error handling](#error-handling)
- [End-to-end example](#end-to-end-example)
- [What next](#what-next)

---

## Why EXOCHAIN

EXOCHAIN is a constitutional trust fabric for AI agents and data sovereignty. Every action — a data share, a vote, a delegation — is adjudicated by an immutable kernel that enforces 8 invariants before the action can take effect. Unlike a conventional policy engine, the invariants are baked into the types: a bailment without scope does not compile; a broken authority chain does not deserialize; a self-grant is rejected by the kernel with a structured verdict that names the violated invariant.

The SDK is the developer-facing facade over the underlying `exo-*` crates (`exo-core`, `exo-identity`, `exo-consent`, `exo-authority`, `exo-governance`, `exo-gatekeeper`). You get a stable, ergonomic API; the fabric gets determinism it can prove. The full constitutional model is documented in [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) and the ten formal proofs in [`docs/proofs/CONSTITUTIONAL-PROOFS.md`](../proofs/CONSTITUTIONAL-PROOFS.md).

---

## Installation

### Workspace path dependency (recommended during development)

If you are building inside the `exochain` workspace, add the SDK as a path dependency:

```toml
# Cargo.toml
[dependencies]
exochain-sdk = { path = "../exochain-sdk" }
```

### Git dependency

If you are consuming EXOCHAIN from an external repo, pin to a tag or revision:

```toml
# Cargo.toml
[dependencies]
exochain-sdk = { git = "https://github.com/exochain/exochain.git", tag = "v0.1.0" }
```

### Verify the install

```rust
// src/main.rs
use exochain_sdk::prelude::*;

fn main() {
    let identity = Identity::generate("hello");
    println!("DID: {}", identity.did());
}
```

```text
$ cargo run
DID: did:exo:a1b2c3d4e5f60789
```

The DID is derived as `did:exo:<first 16 hex chars of BLAKE3(public_key_bytes)>`, so the suffix is random per keypair but always 16 lowercase hex characters.

### Required toolchain

- Rust 1.85+ (edition 2024). See [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md) for the full toolchain setup including `cargo-deny`, `cargo-audit`, and `cargo-tarpaulin`.

---

## The prelude

`exochain_sdk::prelude` re-exports the types you need for 95 percent of SDK work:

```rust
use exochain_sdk::prelude::*;

// Now in scope:
//   Identity, BailmentBuilder
//   DecisionBuilder, Decision, Vote
//   AuthorityChainBuilder
//   hash, sign, verify
//   ConstitutionalKernel
//   ExoError, ExoResult
```

For anything not in the prelude, reach for the module directly:

```rust
use exochain_sdk::authority::{ChainLink, ValidatedChain};
use exochain_sdk::consent::BailmentProposal;
use exochain_sdk::governance::{DecisionClass, DecisionStatus, QuorumResult, VoteChoice};
use exochain_sdk::kernel::KernelVerdict;
```

---

## Domain 1: Identity

An `Identity` pairs an Ed25519 keypair with a DID derived deterministically from the public key. The private key never leaves the struct. Signatures are produced by `sign` and verified with `verify`.

### Generate, sign, verify

```rust
use exochain_sdk::prelude::*;

fn main() {
    let alice = Identity::generate("alice");
    println!("alice.did       = {}", alice.did());
    println!("alice.label     = {}", alice.label());
    println!("alice.public_key = {:?}", alice.public_key());

    let message = b"I, Alice, consent to share my medical records.";
    let signature = alice.sign(message);

    assert!(alice.verify(message, &signature));
    assert!(!alice.verify(b"different message", &signature));
}
```

Expected output:

```text
alice.did       = did:exo:b7c14e2f8a3d1f90
alice.label     = alice
alice.public_key = PublicKey(..32 bytes..)
```

The DID prefix is always `did:exo:`, followed by 16 lowercase hex characters. Two identities generated separately will never collide (the 64-bit prefix of BLAKE3 is collision-resistant for any realistic population).

### Rebuild from a stored keypair

If you persist key material, use `Identity::from_keypair` to reconstruct an identity with the same DID:

```rust
use exochain_sdk::crypto::{PublicKey, SecretKey};
use exochain_sdk::prelude::*;

fn rebuild(public: PublicKey, secret: SecretKey) -> ExoResult<Identity> {
    Identity::from_keypair("restored", public, secret)
}
```

### DID document

A minimal W3C DID document is available via `did_document()` for integration with DID resolvers:

```rust
use exochain_sdk::prelude::*;

fn main() {
    let id = Identity::generate("doc");
    let doc = id.did_document();
    assert_eq!(&doc.id, id.did());
    assert_eq!(doc.public_keys.len(), 1);
    assert!(!doc.revoked);
}
```

---

## Domain 2: Consent (bailments)

A **bailment** is scoped, time-bounded consent from a bailor (grantor) to a bailee (grantee). `BailmentBuilder` constructs and validates a proposal; the resulting `BailmentProposal` carries a deterministic content-addressed ID so two identical proposals produce the same ID.

### Build a bailment proposal

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::crypto::Did;

fn main() -> ExoResult<()> {
    let bailor = Did::new("did:exo:alice").map_err(|e| ExoError::InvalidDid(e.to_string()))?;
    let bailee = Did::new("did:exo:bob").map_err(|e| ExoError::InvalidDid(e.to_string()))?;

    let proposal = BailmentBuilder::new(bailor, bailee)
        .scope("data:medical:records")
        .duration_hours(24)
        .build()?;

    println!("proposal_id     = {}", proposal.proposal_id);
    println!("bailor          = {}", proposal.bailor);
    println!("bailee          = {}", proposal.bailee);
    println!("scope           = {}", proposal.scope);
    println!("duration_hours  = {}", proposal.duration_hours);
    Ok(())
}
```

Expected output:

```text
proposal_id     = f1e2d3c4b5a69780
bailor          = did:exo:alice
bailee          = did:exo:bob
scope           = data:medical:records
duration_hours  = 24
```

### What fails

| Failure | Error |
|---|---|
| `scope` not set | `ExoError::Consent("scope is required")` |
| `scope = ""` | `ExoError::Consent("scope must be non-empty")` |
| `duration_hours` not set | `ExoError::Consent("duration_hours is required")` |
| `duration_hours = 0` | `ExoError::Consent("duration_hours must be > 0")` |

Every validation happens in `.build()`, so you can chain `with`-methods freely and handle errors once.

### Deterministic proposal IDs

The `proposal_id` is the first 16 hex characters of `BLAKE3(bailor || 0 || bailee || 0 || scope || 0 || duration_hours_le)`. Identical inputs always produce identical IDs — useful for idempotent submission and cross-party agreement without a round trip.

---

## Domain 3: Governance (decisions + voting)

Decisions flow through `Proposed -> Deliberating -> Approved | Rejected | Challenged`. Votes are appended with `cast_vote`; duplicate voters are rejected. `check_quorum(threshold)` tallies the votes and reports whether approvals cross the threshold.

### Create a decision

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::crypto::Did;
use exochain_sdk::governance::DecisionClass;

fn main() -> ExoResult<()> {
    let proposer = Did::new("did:exo:alice")
        .map_err(|e| ExoError::InvalidDid(e.to_string()))?;

    let decision = DecisionBuilder::new(
        "Raise quorum threshold to 3/4",
        "Constitutional amendment increasing the supermajority bar.",
        proposer,
    )
    .decision_class(DecisionClass::new("amendment"))
    .build()?;

    println!("decision_id = {}", decision.decision_id);
    println!("status      = {:?}", decision.status);
    println!("class       = {:?}", decision.class);
    Ok(())
}
```

### Cast votes, check quorum

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::crypto::Did;
use exochain_sdk::governance::VoteChoice;

fn main() -> ExoResult<()> {
    let proposer = Did::new("did:exo:alice")
        .map_err(|e| ExoError::InvalidDid(e.to_string()))?;

    let mut decision = DecisionBuilder::new("t", "d", proposer).build()?;

    let v1 = Did::new("did:exo:validator1")
        .map_err(|e| ExoError::InvalidDid(e.to_string()))?;
    let v2 = Did::new("did:exo:validator2")
        .map_err(|e| ExoError::InvalidDid(e.to_string()))?;
    let v3 = Did::new("did:exo:validator3")
        .map_err(|e| ExoError::InvalidDid(e.to_string()))?;

    decision.cast_vote(Vote::new(v1, VoteChoice::Approve))?;
    decision.cast_vote(Vote::new(v2, VoteChoice::Approve).with_rationale("LGTM"))?;
    decision.cast_vote(Vote::new(v3, VoteChoice::Reject))?;

    let quorum = decision.check_quorum(2);
    println!("met         = {}", quorum.met);
    println!("approvals   = {}", quorum.approvals);
    println!("rejections  = {}", quorum.rejections);
    println!("abstentions = {}", quorum.abstentions);
    println!("total_votes = {}", quorum.total_votes);
    Ok(())
}
```

Expected output:

```text
met         = true
approvals   = 2
rejections  = 1
abstentions = 0
total_votes = 3
```

### Duplicate voters are rejected

```rust
let v1 = Did::new("did:exo:validator1").unwrap();
decision.cast_vote(Vote::new(v1.clone(), VoteChoice::Approve))?;
let err = decision
    .cast_vote(Vote::new(v1, VoteChoice::Reject))
    .unwrap_err();
assert!(matches!(err, ExoError::Governance(_)));
```

This matters: one-DID-one-vote is invariant-level in the fabric. See `QuorumLegitimate` in the [invariants](#kernel-invariants).

---

## Domain 4: Authority chains

An authority chain is an ordered list of delegation links where each `grantee` is the next `grantor`. The chain terminates at a specific actor. `AuthorityChainBuilder` validates topology in `.build()`.

### Build and validate

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::crypto::Did;

fn main() -> ExoResult<()> {
    let root = Did::new("did:exo:root").map_err(|e| ExoError::InvalidDid(e.to_string()))?;
    let mid  = Did::new("did:exo:mid").map_err(|e| ExoError::InvalidDid(e.to_string()))?;
    let leaf = Did::new("did:exo:leaf").map_err(|e| ExoError::InvalidDid(e.to_string()))?;

    let chain = AuthorityChainBuilder::new()
        .add_link(root.clone(), mid.clone(), vec!["read".into()])
        .add_link(mid.clone(),  leaf.clone(), vec!["read".into(), "write".into()])
        .build(&leaf)?;

    println!("depth     = {}", chain.depth);
    println!("terminal  = {}", chain.terminal);
    for (i, link) in chain.links.iter().enumerate() {
        println!("  link[{i}]: {} -> {} [{}]",
            link.grantor, link.grantee, link.permissions.join(", "));
    }
    Ok(())
}
```

Expected output:

```text
depth     = 2
terminal  = did:exo:leaf
  link[0]: did:exo:root -> did:exo:mid [read]
  link[1]: did:exo:mid -> did:exo:leaf [read, write]
```

### Validation rules

| Rule | Violation | Error |
|---|---|---|
| At least one link | `build()` on empty builder | `ExoError::Authority("authority chain is empty")` |
| Consecutive links connect | `links[i].grantee != links[i+1].grantor` | `ExoError::Authority("broken delegation: X != Y")` |
| Final grantee matches terminal | `last.grantee != terminal_actor` | `ExoError::Authority("terminal mismatch: ...")` |

### Broken chain example

```rust
let root = Did::new("did:exo:root").unwrap();
let mid  = Did::new("did:exo:mid").unwrap();
let bogus = Did::new("did:exo:bogus").unwrap();
let leaf = Did::new("did:exo:leaf").unwrap();

let err = AuthorityChainBuilder::new()
    .add_link(root,  mid.clone(), vec!["read".into()])
    .add_link(bogus, leaf.clone(), vec!["read".into()])  // bogus != mid
    .build(&leaf)
    .unwrap_err();
assert!(matches!(err, ExoError::Authority(_)));
```

---

## Domain 5: Crypto primitives

The SDK re-exports `sign`, `verify`, `generate_keypair`, `hash`, and `hash_hex` for when you need to work below the `Identity` abstraction. Hashing is BLAKE3, signing is Ed25519.

### Hashing

```rust
use exochain_sdk::crypto::{hash, hash_hex};

fn main() {
    let bytes = hash(b"hello");             // [u8; 32]
    let hex   = hash_hex(b"hello");         // 64-char lowercase hex String
    assert_eq!(bytes.len(), 32);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}
```

### Raw sign/verify

```rust
use exochain_sdk::crypto::{generate_keypair, sign, verify};

fn main() {
    let (pk, sk) = generate_keypair();
    let msg = b"authenticated message";
    let sig = sign(msg, &sk);
    assert!(verify(msg, &sig, &pk));
    assert!(!verify(b"tampered", &sig, &pk));
}
```

---

## Domain 6: Constitutional kernel

`ConstitutionalKernel` wraps `exo_gatekeeper::Kernel` with permissive defaults suitable for the common case: a single actor, a judicial role, a one-link authority chain rooted at `did:exo:root`, an active bailment, and signed provenance. Call `adjudicate(&actor, "action-name")` and match on the `KernelVerdict`.

### The three outcomes

```rust
use exochain_sdk::kernel::{ConstitutionalKernel, KernelVerdict};
use exochain_sdk::crypto::Did;

fn main() {
    let kernel = ConstitutionalKernel::new();
    assert_eq!(kernel.invariant_count(), 8);
    assert!(kernel.verify_integrity()); // constitution hash still matches

    let actor = Did::new("did:exo:actor").unwrap();

    // 1. Permitted — valid action, valid context.
    match kernel.adjudicate(&actor, "read-medical-record") {
        KernelVerdict::Permitted => println!("permitted"),
        other => panic!("expected Permitted, got {other:?}"),
    }

    // 2. Denied — self-grant violates NoSelfGrant.
    match kernel.adjudicate_self_grant(&actor, "escalate-self") {
        KernelVerdict::Denied { violations } => {
            println!("denied. violations:");
            for v in &violations {
                println!("  - {v}");
            }
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    // 3. Denied — kernel modification violates KernelImmutability.
    let v = kernel.adjudicate_kernel_modification(&actor, "patch-kernel");
    assert!(v.is_denied());

    // 4. Denied — missing consent violates ConsentRequired.
    let v = kernel.adjudicate_without_bailment(&actor, "read-data");
    assert!(v.is_denied());
}
```

Expected output (violations strings are kernel-generated, format stable):

```text
permitted
denied. violations:
  - NoSelfGrant: actor attempted to grant permissions to themselves
```

### Kernel invariants

Eight constitutional invariants are checked on every adjudication. They are:

1. **SeparationOfPowers** — no actor holds legislative + executive + judicial authority simultaneously.
2. **ConsentRequired** — every action needs an active bailment record linking actor to resource.
3. **NoSelfGrant** — an actor cannot expand its own permissions.
4. **HumanOverride** — emergency human intervention must remain possible.
5. **KernelImmutability** — the constitution and invariant set are byte-stable after construction.
6. **AuthorityChainValid** — the chain from root to actor must be cryptographically valid and unbroken.
7. **QuorumLegitimate** — quorum evidence must meet the declared threshold.
8. **ProvenanceVerifiable** — every action carries a verifiable provenance record.

The kernel also checks the 6 MCP enforcement rules (`Mcp001BctsScope`, `Mcp002NoSelfEscalation`, `Mcp003ProvenanceRequired`, `Mcp004NoIdentityForge`, `Mcp005Distinguishable`, `Mcp006ConsentBoundaries`) when an AI actor is the request origin. See [`docs/guides/mcp-integration.md`](./mcp-integration.md) for the full list.

### Getting Escalated

The third verdict, `KernelVerdict::Escalated { reason }`, surfaces when the kernel cannot decide unilaterally — typically because a challenge is active. For the `adjudicate*` helpers in the SDK, you will normally only see `Permitted` or `Denied`; `Escalated` is produced by the underlying kernel when you supply an `active_challenge_reason` via the full `exo_gatekeeper::Kernel` API.

---

## Error handling

Every fallible SDK operation returns `ExoResult<T>`, an alias for `Result<T, ExoError>`. The variants narrow to a specific subsystem:

```rust
use exochain_sdk::error::{ExoError, ExoResult};

fn describe(err: &ExoError) -> &'static str {
    match err {
        ExoError::Identity(_)       => "identity / DID / keypair",
        ExoError::Consent(_)        => "bailment / consent",
        ExoError::Governance(_)     => "decision / voting",
        ExoError::Authority(_)      => "authority chain",
        ExoError::KernelDenied(_)   => "kernel denied the action",
        ExoError::KernelEscalated(_)=> "kernel escalated for review",
        ExoError::Crypto(_)         => "hash / sign / verify",
        ExoError::InvalidDid(_)     => "DID string rejected",
        ExoError::Serialization(_)  => "serde failure",
    }
}
```

Each variant wraps a `String` with enough context to diagnose the failure from the error alone. `ExoError` implements `std::error::Error` via `thiserror`, so it composes cleanly with `anyhow`, `eyre`, and custom error types in caller code.

### Typical error-handling patterns

**Propagate with `?`:**

```rust
use exochain_sdk::prelude::*;

fn build_proposal(bailor: exochain_sdk::crypto::Did, bailee: exochain_sdk::crypto::Did)
    -> ExoResult<exochain_sdk::consent::BailmentProposal>
{
    BailmentBuilder::new(bailor, bailee)
        .scope("data:medical")
        .duration_hours(24)
        .build()
}
```

**Match on specific variants:**

```rust
match decision.cast_vote(vote) {
    Ok(()) => println!("vote recorded"),
    Err(ExoError::Governance(reason)) => eprintln!("governance rejected: {reason}"),
    Err(other) => eprintln!("unexpected error: {other}"),
}
```

**Convert `exo_core::Did` errors:**

`exo_core::Did::new` returns its own error type. Convert into `ExoError::InvalidDid`:

```rust
use exochain_sdk::error::{ExoError, ExoResult};
use exochain_sdk::crypto::Did;

fn parse_did(s: &str) -> ExoResult<Did> {
    Did::new(s).map_err(|e| ExoError::InvalidDid(e.to_string()))
}
```

---

## End-to-end example

This is the pattern every production caller follows: create an identity, propose a bailment, build a decision, collect votes, check quorum, and run an adjudication through the kernel.

```rust
use exochain_sdk::crypto::Did;
use exochain_sdk::governance::{DecisionClass, VoteChoice};
use exochain_sdk::kernel::KernelVerdict;
use exochain_sdk::prelude::*;

fn parse_did(s: &str) -> ExoResult<Did> {
    Did::new(s).map_err(|e| ExoError::InvalidDid(e.to_string()))
}

fn main() -> ExoResult<()> {
    // 1. Identity.
    let alice = Identity::generate("alice");
    let bob   = Identity::generate("bob");
    println!("alice = {}", alice.did());
    println!("bob   = {}", bob.did());

    // 2. Bailment: Alice grants Bob 24h of read on medical records.
    let proposal = BailmentBuilder::new(alice.did().clone(), bob.did().clone())
        .scope("data:medical:records")
        .duration_hours(24)
        .build()?;
    println!("bailment proposal {}", proposal.proposal_id);

    // 3. Governance decision: should we expand Bob's scope?
    let mut decision = DecisionBuilder::new(
        "Expand Bob's read scope to imaging",
        "Bob requests access to imaging in addition to records.",
        alice.did().clone(),
    )
    .decision_class(DecisionClass::new("scope-expansion"))
    .build()?;

    // 4. Three validators vote.
    for (i, choice) in [VoteChoice::Approve, VoteChoice::Approve, VoteChoice::Reject]
        .iter()
        .enumerate()
    {
        let v = parse_did(&format!("did:exo:v{i}"))?;
        decision.cast_vote(Vote::new(v, *choice))?;
    }
    let q = decision.check_quorum(2);
    println!("quorum met = {} ({}/{} approvals)", q.met, q.approvals, q.total_votes);

    // 5. Authority chain: root delegates to Alice, Alice to Bob.
    let root = parse_did("did:exo:root")?;
    let chain = AuthorityChainBuilder::new()
        .add_link(root,              alice.did().clone(), vec!["read".into(), "delegate".into()])
        .add_link(alice.did().clone(), bob.did().clone(), vec!["read".into()])
        .build(bob.did())?;
    println!("chain depth = {}", chain.depth);

    // 6. Kernel adjudicates Bob's action.
    let kernel = ConstitutionalKernel::new();
    match kernel.adjudicate(bob.did(), "read-medical-record") {
        KernelVerdict::Permitted => println!("kernel permitted"),
        KernelVerdict::Denied { violations } => {
            for v in violations { println!("denied: {v}"); }
        }
        KernelVerdict::Escalated { reason } => println!("escalated: {reason}"),
    }

    Ok(())
}
```

Expected output (DIDs and IDs will differ between runs):

```text
alice = did:exo:d9c21e4b7f1a8035
bob   = did:exo:a0314e8c7f9b2d11
bailment proposal 4f2a910b8c6d7e08
quorum met = true (2/3 approvals)
chain depth = 2
kernel permitted
```

---

## What next

- **TypeScript SDK** — [`docs/guides/sdk-quickstart-typescript.md`](./sdk-quickstart-typescript.md). Same primitives, browser + Node.
- **Python SDK** — [`docs/guides/sdk-quickstart-python.md`](./sdk-quickstart-python.md). Pydantic + asyncio.
- **MCP integration** — [`docs/guides/mcp-integration.md`](./mcp-integration.md). Wire Claude or another MCP client to the node's 40 tools + 6 resources + 4 prompts.
- **Getting Started** — [`docs/guides/GETTING-STARTED.md`](./GETTING-STARTED.md). Workspace build, CI gates, council process.
- **Architecture** — [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md). The 3-branch model, BCTS lifecycle, crate graph.
- **Crate reference** — [`docs/reference/CRATE-REFERENCE.md`](../reference/CRATE-REFERENCE.md). Full API per crate.
- **Constitutional proofs** — [`docs/proofs/CONSTITUTIONAL-PROOFS.md`](../proofs/CONSTITUTIONAL-PROOFS.md). The ten formal proofs that the invariants hold.
- **Source** — [`crates/exochain-sdk/src/`](../../crates/exochain-sdk/src/). Every module is under 300 lines of Rust.

---

Licensed under Apache-2.0. © 2025 EXOCHAIN Foundation.
