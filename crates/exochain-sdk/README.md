# exochain-sdk

Ergonomic Rust API for the **EXOCHAIN constitutional governance fabric** — a
substrate for AI agents and data sovereignty built around decentralized
identifiers (DIDs), scoped consent (bailments), authority-chain delegation,
quorum-based governance, and a constitutional kernel that enforces policy
*before* action rather than auditing it after. The SDK wraps the lower-level
`exo-*` workspace crates behind a single, developer-friendly surface so that
applications depend on one crate and one coherent API.

## Installation

### Workspace (recommended inside the monorepo)

Inside the EXOCHAIN monorepo, add the crate as a path dependency:

```toml
[dependencies]
exochain-sdk = { path = "../exochain-sdk" }
```

### Git dependency

```toml
[dependencies]
exochain-sdk = { git = "https://github.com/exochain/exochain", branch = "main" }
```

### crates.io (planned)

Once published, the SDK will be installable with:

```bash
cargo add exochain-sdk
```

Minimum supported Rust version (MSRV) is inherited from the workspace.

## Quick start

The canonical end-to-end flow: two identities negotiate a bailment, propose a
decision, reach quorum, build a delegation chain, and submit an action to the
kernel for adjudication.

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::governance::VoteChoice;

fn main() -> Result<(), ExoError> {
    // 1. Create identities for alice and bob.
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");

    // 2. Alice proposes a scoped, time-bounded bailment to bob.
    let proposal = BailmentBuilder::new(alice.did().clone(), bob.did().clone())
        .scope("data:medical")
        .duration_hours(24)
        .build()?;
    println!("proposal id: {}", proposal.proposal_id);

    // 3. Alice proposes a decision; bob and carol approve.
    let carol = Identity::generate("carol");
    let mut decision = DecisionBuilder::new(
        "Ratify bailment",
        "Allow bob to read medical records for 24h",
        alice.did().clone(),
    )
    .build()?;
    decision.cast_vote(Vote::new(bob.did().clone(), VoteChoice::Approve))?;
    decision.cast_vote(Vote::new(carol.did().clone(), VoteChoice::Approve))?;
    let quorum = decision.check_quorum(2);
    assert!(quorum.met);

    // 4. Build an authority chain: root -> alice -> bob.
    let root = Identity::generate("root");
    let chain = AuthorityChainBuilder::new()
        .add_link(root.did().clone(), alice.did().clone(), vec!["delegate".into()])
        .add_link(alice.did().clone(), bob.did().clone(), vec!["read".into()])
        .build(bob.did())?;
    assert_eq!(chain.depth, 2);

    // 5. Ask the kernel whether bob may perform the action.
    // The SDK kernel requires caller-supplied authority signing material.
    let kernel = ConstitutionalKernel::with_authority_identity(root);
    let verdict = kernel.adjudicate(bob.did(), "data:medical:read");
    assert!(verdict.is_permitted());

    Ok(())
}
```

The crate-level Rustdoc contains the same example as a runnable doctest — see
`cargo doc --open -p exochain-sdk`.

## Module layout

The SDK is organized by domain. Each module is independently usable, but they
are most powerful together:

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| [`identity`](src/identity.rs)     | DID-backed Ed25519 identities (generate, sign, verify).      |
| [`consent`](src/consent.rs)       | Scoped, time-bounded bailments (consent tokens).             |
| [`governance`](src/governance.rs) | Decisions, votes, quorum checks.                             |
| [`authority`](src/authority.rs)   | Delegation chain builder and topology validation.            |
| [`kernel`](src/kernel.rs)         | The Constitutional Governance Runtime (CGR) kernel facade.   |
| [`crypto`](src/crypto.rs)         | BLAKE3 hashing and Ed25519 sign/verify primitives.           |
| [`error`](src/error.rs)           | Single `ExoError` type and `ExoResult<T>` alias.             |

A `prelude` module re-exports the symbols most applications need:

```rust
use exochain_sdk::prelude::*;
// Brings in: Identity, BailmentBuilder, DecisionBuilder, Decision, Vote,
// AuthorityChainBuilder, ConstitutionalKernel, ExoError, ExoResult,
// hash, sign, verify.
```

## Identity

[`Identity`](src/identity.rs) is a DID paired with an Ed25519 keypair and a
human-readable label. The DID is derived from the public key:

```text
did:exo: + first 16 hex chars of BLAKE3(public_key_bytes)
```

```rust
use exochain_sdk::identity::Identity;

let alice = Identity::generate("alice");
println!("did = {}", alice.did());

let sig = alice.sign(b"hello");
assert!(alice.verify(b"hello", &sig));
```

The `Debug` impl redacts the secret key, so `Identity` is safe to log. Use
`Identity::from_keypair` to rehydrate an identity from a persisted keypair.

## Consent (bailments)

A bailment is scoped, time-bounded consent from a bailor to a bailee. The
[`BailmentBuilder`](src/consent.rs) validates inputs and produces a
deterministic, content-addressed proposal.

```rust
use exochain_sdk::consent::BailmentBuilder;
use exo_core::Did;

let alice = Did::new("did:exo:alice").expect("valid");
let bob = Did::new("did:exo:bob").expect("valid");

let proposal = BailmentBuilder::new(alice, bob)
    .scope("data:medical")
    .duration_hours(24)
    .build()
    .expect("valid proposal");
```

`proposal.proposal_id` is a BLAKE3-derived 16-char hex string; two parties
independently building the same proposal get the same ID with no coordination.

## Governance (decisions, voting, quorum)

[`DecisionBuilder`](src/governance.rs) constructs a decision; the decision
accumulates votes via `cast_vote` and reports quorum with `check_quorum`.

```rust
use exochain_sdk::governance::{DecisionBuilder, Vote, VoteChoice};
use exo_core::Did;

let proposer = Did::new("did:exo:alice").expect("valid");
let v1 = Did::new("did:exo:v1").expect("valid");
let v2 = Did::new("did:exo:v2").expect("valid");

let mut d = DecisionBuilder::new("Ratify v1", "Promote to prod", proposer)
    .build()
    .expect("valid");
d.cast_vote(Vote::new(v1, VoteChoice::Approve)).unwrap();
d.cast_vote(Vote::new(v2, VoteChoice::Approve)).unwrap();

let q = d.check_quorum(2);
assert!(q.met);
```

The same voter may cast at most one vote; a second attempt returns
`ExoError::Governance`.

## Authority chains

An authority chain is an ordered list of delegation links where
`links[i].grantee == links[i+1].grantor`. The
[`AuthorityChainBuilder`](src/authority.rs) validates the topology on
`build`.

```rust
use exochain_sdk::authority::AuthorityChainBuilder;
use exo_core::Did;

let root = Did::new("did:exo:root").expect("valid");
let mid = Did::new("did:exo:mid").expect("valid");
let leaf = Did::new("did:exo:leaf").expect("valid");

let chain = AuthorityChainBuilder::new()
    .add_link(root, mid.clone(), vec!["delegate".into()])
    .add_link(mid, leaf.clone(), vec!["read".into()])
    .build(&leaf)
    .expect("valid");

assert_eq!(chain.depth, 2);
```

`build` returns `ExoError::Authority` for empty chains, broken links, or a
terminal mismatch.

## Constitutional kernel

[`ConstitutionalKernel`](src/kernel.rs) is a simplified wrapper over
[`exo_gatekeeper::Kernel`]. It initialises the kernel with the default
EXOCHAIN constitution and all eight invariants. Adjudication requires
caller-supplied authority signing material, so the SDK does not fabricate a
trust root.

```rust
use exochain_sdk::kernel::ConstitutionalKernel;
use exochain_sdk::identity::Identity;
use exo_core::Did;

let authority = Identity::generate("authority");
let kernel = ConstitutionalKernel::with_authority_identity(authority);
let actor = Did::new("did:exo:alice").expect("valid");

let verdict = kernel.adjudicate(&actor, "data:medical:read");
assert!(verdict.is_permitted());
```

The SDK supplies a minimal signed default context (single Judicial role,
one-link authority chain, active bailment, preserved human override). Targeted
helpers exercise specific invariants:

- `adjudicate_self_grant` — enables `NoSelfGrant` enforcement.
- `adjudicate_kernel_modification` — enables `KernelImmutability` enforcement.
- `adjudicate_without_bailment` — enables `ConsentRequired` enforcement.

Callers needing fine-grained control over the full adjudication context
should use [`exo_gatekeeper::Kernel`] directly.

## Crypto helpers

The [`crypto`](src/crypto.rs) module re-exports the foundational types and
provides convenience helpers:

```rust
use exochain_sdk::crypto::{generate_keypair, hash, hash_hex, sign, verify};

let digest = hash(b"hello");            // [u8; 32] BLAKE3
let hex = hash_hex(b"hello");           // 64-char lowercase hex

let (pk, sk) = generate_keypair();      // Ed25519
let sig = sign(b"payload", &sk);
assert!(verify(b"payload", &sig, &pk));
```

## Error handling

All fallible SDK operations return `ExoResult<T>` — an alias for
`Result<T, ExoError>`. Each error variant narrows the failure to a specific
subsystem so callers can pattern-match without parsing strings:

| Variant                     | When returned                                              |
| --------------------------- | ---------------------------------------------------------- |
| `ExoError::Identity`        | Identity flows that could validate caller-supplied material.|
| `ExoError::Consent`         | `BailmentBuilder::build` — missing/empty scope, zero duration. |
| `ExoError::Governance`      | Empty decision title, duplicate voter.                     |
| `ExoError::Authority`       | Empty chain, broken delegation, terminal mismatch.         |
| `ExoError::KernelDenied`    | Optional lift of kernel denial into the error channel.     |
| `ExoError::KernelEscalated` | Optional lift of kernel escalation into the error channel. |
| `ExoError::Crypto`          | Reserved for future fallible crypto flows.                 |
| `ExoError::InvalidDid`      | DID-string validation failure (unreachable in practice).   |
| `ExoError::Serialization`   | Reserved for wire-payload marshal wrappers.                |

```rust
use exochain_sdk::prelude::*;
use exochain_sdk::error::ExoError;
use exo_core::Did;

let a = Did::new("did:exo:a").unwrap();
let b = Did::new("did:exo:b").unwrap();
let err = BailmentBuilder::new(a, b).build().unwrap_err();
assert!(matches!(err, ExoError::Consent(_)));
```

## Cross-language SDKs

EXOCHAIN ships three first-party SDKs that share the same model and wire
format:

- **Rust** (this crate) — `crates/exochain-sdk`. The reference
  implementation; uses BLAKE3 for hashing.
- **TypeScript** — `packages/exochain-sdk`, published as `@exochain/sdk`.
  Uses SHA-256 because Web Crypto does not ship BLAKE3.
- **Python** — `packages/exochain-py`, published as `exochain` on PyPI. Also
  uses SHA-256 for parity with the browser SDK.

DIDs derived locally by the Rust SDK will **not** match DIDs derived by the
TypeScript or Python SDKs for the same keypair. Applications that need
canonical DIDs across all three SDKs should resolve the DID from the fabric
rather than deriving it locally.

## MCP server integration

EXOCHAIN ships an MCP (Model Context Protocol) server at `exo-node` for use
with AI agents — it exposes EXOCHAIN's identity, consent, governance, and
kernel primitives as MCP tools so LLM agents can request, delegate, and
adjudicate actions through the same constitutional surface.

This SDK targets application developers writing Rust services that speak to
EXOCHAIN directly. When integrating with the MCP server, the SDK's types
serve as the canonical Rust representation of the objects the MCP server
accepts and returns.

## Development

Run from the monorepo root:

```bash
# Unit and integration tests
cargo test -p exochain-sdk

# Doctests
cargo test --doc -p exochain-sdk

# Docs with intra-doc link checking
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc -p exochain-sdk --no-deps

# Lints
cargo clippy -p exochain-sdk --all-targets -- -D warnings
```

## Related crates

The SDK wraps these lower-level crates; use them directly when you need
access beyond the SDK's surface:

- `exo-core` — foundational types (DID, Hash256, Signature, Timestamp, HLC).
- `exo-identity` — DID documents and privacy-preserving identity adjudication.
- `exo-consent` — bailment-conditioned consent enforcement.
- `exo-authority` — authority-chain verification and delegation.
- `exo-governance` — legislative legitimacy: quorum, clearance, crosscheck.
- `exo-gatekeeper` — CGR kernel, invariant enforcement, MCP middleware.
- `exo-escalation` — operational nervous system.
- `exo-legal` — litigation-grade evidence and eDiscovery.
- `exo-dag` — append-only DAG with BFT consensus.
- `exo-proofs` — SNARK, STARK, ZKML verifier.

See `crates/README.md` for the full crate index.

## License

Licensed under **Apache-2.0**. See the top-level `LICENSE` file for the full
text.
